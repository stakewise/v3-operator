import asyncio
from contextlib import contextmanager
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber, ChecksumAddress
from hexbytes import HexBytes
from sw_utils.tests import faker
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Gwei, Wei

from src.commands.internal.process_redeemer import (
    _build_meta_vault_redeem_order,
    _process_exit_queue,
    _redeem_meta_vault_sub_vaults,
    _startup_check,
    _submit_update_vault_state,
    _build_multi_proof,
    calculate_redeemable_shares,
    fetch_positions_from_ipfs,
    process,
    redeem_positions,
    update_vaults_state,
)
from src.common.typings import HarvestParams
from src.meta_vault.typings import SubVaultRedemption
from src.redemptions.os_token_converter import OsTokenConverter
from src.redemptions.typings import OsTokenPosition

MODULE = 'src.commands.internal.process_redeemer'

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
VAULT_2 = Web3.to_checksum_address('0x' + '22' * 20)
VAULT_3 = Web3.to_checksum_address('0x' + '55' * 20)
OWNER_1 = Web3.to_checksum_address('0x' + '33' * 20)
OWNER_2 = Web3.to_checksum_address('0x' + '44' * 20)
REGISTRY_1 = Web3.to_checksum_address('0x' + '66' * 20)


# --- Pure function tests (no mocks) ---


class TestBuildMultiProof:
    def test_single_position(self) -> None:
        position = make_position(leaf_shares=1000, unprocessed_shares=500)
        result = _build_multi_proof(
            tree_nonce=5,
            all_positions=[position],
            positions_to_redeem=[position],
        )
        assert len(result.leaves) == 1

    def test_partial_redeem(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000, unprocessed_shares=500)
        pos2 = make_position(
            vault=VAULT_2, owner=OWNER_2, leaf_shares=2000, unprocessed_shares=1000
        )

        result = _build_multi_proof(
            tree_nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1],
        )
        assert len(result.leaves) == 1
        assert len(result.proof) > 0

    def test_all_positions_redeemed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000, unprocessed_shares=500)
        pos2 = make_position(
            vault=VAULT_2, owner=OWNER_2, leaf_shares=2000, unprocessed_shares=1000
        )

        result = _build_multi_proof(
            tree_nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1, pos2],
        )
        assert len(result.leaves) == 2


class TestRedeemPositions:
    async def test_empty_positions(self) -> None:
        with _mock_redeem_positions() as mocks:
            await redeem_positions(
                all_positions=[],
                os_token_positions=[],
                queued_shares=10000,
                converter=make_converter(),
                nonce=5,
            )
        mocks['tx_mock'].assert_not_called()

    async def test_single_position_sufficient_assets(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(1000)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(),
                nonce=5,
            )

        assert mocks['tx_mock'].await_count == 1
        positions_arg = _captured_positions_arg(mocks)
        assert positions_arg[0][3] == Wei(500)  # shares_to_redeem

    async def test_single_position_insufficient_assets_partial_fill(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(100)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                nonce=5,
            )

        assert mocks['tx_mock'].await_count == 1
        positions_arg = _captured_positions_arg(mocks)
        assert positions_arg[0][3] == Wei(100)

    async def test_single_position_zero_withdrawable_skipped(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(0)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                nonce=5,
            )

        mocks['tx_mock'].assert_not_called()

    async def test_queued_shares_limits_redemption(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=200,
                converter=make_converter(),
                nonce=5,
            )

        assert mocks['tx_mock'].await_count == 1
        positions_arg = _captured_positions_arg(mocks)
        assert positions_arg[0][3] == Wei(200)

    async def test_multiple_positions_share_vault_cache(self) -> None:
        """Withdrawable is fetched once per vault, decremented after each redemption."""
        pos1 = make_position(owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(owner=OWNER_2, unprocessed_shares=1000)

        get_withdrawable = AsyncMock(return_value=Wei(700))
        with _mock_redeem_positions(get_withdrawable=get_withdrawable) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                nonce=5,
            )

        # Two redemption transactions (one per position)
        assert mocks['tx_mock'].await_count == 2
        # Single fetch — second position uses cached value
        assert get_withdrawable.await_count == 1

        first_position = mocks['tx_calls'][0][0][0]
        second_position = mocks['tx_calls'][1][0][0]
        assert first_position[1] == OWNER_1 and first_position[3] == Wei(500)
        assert second_position[1] == OWNER_2 and second_position[3] == Wei(200)

    async def test_stops_across_vaults_when_queued_shares_exhausted(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=800)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=500,
                converter=make_converter(100, 100),
                nonce=5,
            )

        # Only the first position's vault is redeemed
        assert mocks['tx_mock'].await_count == 1
        positions_arg = _captured_positions_arg(mocks)
        assert positions_arg[0][0] == VAULT_1

    async def test_preserves_original_leaf_shares_in_call(self) -> None:
        pos = make_position(leaf_shares=1000, unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=200,
                converter=make_converter(),
                nonce=5,
            )

        positions_arg = _captured_positions_arg(mocks)
        # leafShares preserved, sharesToRedeem capped by queued_shares
        assert positions_arg[0][2] == Wei(1000)
        assert positions_arg[0][3] == Wei(200)

    async def test_meta_vault_redeem_sub_vaults_when_short(self) -> None:
        """Meta vault short on withdrawable triggers sub-vault redemption then refetches."""
        pos = make_position(unprocessed_shares=500)
        # First call: short. Second call (post sub-vault redeem): plenty.
        get_withdrawable = AsyncMock(side_effect=[Wei(100), Wei(1000)])

        with (
            _mock_redeem_positions(get_withdrawable=get_withdrawable, is_meta_vault=True) as mocks,
            patch(f'{MODULE}._redeem_meta_vault_sub_vaults', new=AsyncMock()) as mock_redeem_sub,
        ):
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=10000,
                converter=make_converter(100, 100),
                nonce=5,
            )

        mock_redeem_sub.assert_awaited_once()
        assert get_withdrawable.await_count == 2
        positions_arg = _captured_positions_arg(mocks)
        assert positions_arg[0][3] == Wei(500)

    async def test_meta_vault_redeem_still_short_partial_fill(self) -> None:
        """Sub-vault redemption helped but didn't fully cover — partial fill."""
        pos = make_position(unprocessed_shares=500)
        get_withdrawable = AsyncMock(side_effect=[Wei(100), Wei(300)])

        with (
            _mock_redeem_positions(get_withdrawable=get_withdrawable, is_meta_vault=True) as mocks,
            patch(f'{MODULE}._redeem_meta_vault_sub_vaults', new=AsyncMock()),
        ):
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=10000,
                converter=make_converter(100, 100),
                nonce=5,
            )

        positions_arg = _captured_positions_arg(mocks)
        assert positions_arg[0][3] == Wei(300)

    async def test_web3_exception_aborts_iteration(self) -> None:
        """A failed redemption aborts the loop; subsequent positions are not attempted."""
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=500)

        with _mock_redeem_positions(
            withdrawable=Wei(10000),
            tx_side_effects=[Web3Exception('boom'), b'\x02' * 32],
        ) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                nonce=5,
            )

        # Only the first position is attempted; loop aborted
        assert mocks['tx_mock'].await_count == 1

    async def test_tx_receipt_failure_aborts_iteration(self) -> None:
        """A failed receipt aborts the loop; subsequent positions are not attempted."""
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000), tx_status=0) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                nonce=5,
            )

        # Only the first position is attempted
        assert mocks['tx_mock'].await_count == 1


# --- Async function tests (with mocks) ---


class TestFetchPositionsFromIpfs:
    async def test_empty_positions(self) -> None:
        async def empty_gen(block_number: BlockNumber | None = None):  # type: ignore[misc]
            return
            yield  # noqa: unreachable

        with patch(f'{MODULE}.iter_os_token_positions', side_effect=empty_gen):
            result = await fetch_positions_from_ipfs(block_number=BlockNumber(100))
        assert result == []

    async def test_returns_all_positions(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, leaf_shares=2000)

        async def gen(block_number: BlockNumber | None = None):  # type: ignore[misc]
            yield pos1
            yield pos2

        with patch(f'{MODULE}.iter_os_token_positions', side_effect=gen):
            result = await fetch_positions_from_ipfs(block_number=BlockNumber(100))
        assert len(result) == 2
        assert result[0] is pos1
        assert result[1] is pos2


class TestCalculateRedeemableShares:
    async def test_all_shares_processed(self) -> None:
        pos = make_position(leaf_shares=1000)
        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(1000)]),
        ):
            result = await calculate_redeemable_shares(
                [pos], nonce=5, block_number=BlockNumber(100)
            )
        assert result == []

    async def test_partial_processed_shares(self) -> None:
        pos = make_position(leaf_shares=1000)
        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(300)]),
        ):
            result = await calculate_redeemable_shares(
                [pos], nonce=5, block_number=BlockNumber(100)
            )
        assert len(result) == 1
        assert result[0].unprocessed_shares == Wei(700)
        assert result[0].leaf_shares == Wei(1000)

    async def test_multiple_positions_mixed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, leaf_shares=2000)

        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(1000), Wei(500)]),
        ):
            result = await calculate_redeemable_shares(
                [pos1, pos2], nonce=5, block_number=BlockNumber(100)
            )
        assert len(result) == 1
        assert result[0].owner == OWNER_2
        assert result[0].unprocessed_shares == Wei(1500)


class TestUpdateVaultsState:
    async def test_no_vaults(self) -> None:
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)) as m_is_meta,
            patch(
                f'{MODULE}.get_multiple_harvest_params', new=AsyncMock(return_value={})
            ) as m_params,
        ):
            await update_vaults_state(vaults=[], block_number=BlockNumber(100))
        m_is_meta.assert_not_called()
        m_params.assert_not_called()

    async def test_meta_vault_needs_harvest(self) -> None:
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(
                f'{MODULE}.is_meta_vault_state_update_required',
                new=AsyncMock(return_value=False),
            ),
            patch(f'{MODULE}.harvest_meta_vault', new=AsyncMock()) as mock_harvest,
            patch(f'{MODULE}.get_multiple_harvest_params', new=AsyncMock(return_value={})),
        ):
            await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))
        mock_harvest.assert_awaited_once_with(VAULT_1)

    async def test_meta_vault_already_up_to_date(self) -> None:
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(
                f'{MODULE}.is_meta_vault_state_update_required',
                new=AsyncMock(return_value=True),
            ),
            patch(f'{MODULE}.harvest_meta_vault', new=AsyncMock()) as mock_harvest,
            patch(f'{MODULE}.get_multiple_harvest_params', new=AsyncMock(return_value={})),
        ):
            await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))
        mock_harvest.assert_not_called()

    async def test_regular_vault_with_harvest_params(self) -> None:
        params = make_harvest_params()
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)),
            patch(
                f'{MODULE}.get_multiple_harvest_params',
                new=AsyncMock(return_value={VAULT_1: params}),
            ),
            patch(f'{MODULE}._submit_update_vault_state', new=AsyncMock()) as mock_submit,
        ):
            await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))
        mock_submit.assert_awaited_once_with(vault=VAULT_1, harvest_params=params)

    async def test_regular_vault_no_harvest_params(self) -> None:
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)),
            patch(
                f'{MODULE}.get_multiple_harvest_params',
                new=AsyncMock(return_value={VAULT_1: None}),
            ),
            patch(f'{MODULE}._submit_update_vault_state', new=AsyncMock()) as mock_submit,
        ):
            await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))
        mock_submit.assert_not_called()

    async def test_mix_of_meta_and_regular_vaults(self) -> None:
        """Meta vault is harvested, regular vault gets updateState; harvest params
        are fetched only for the regular vaults."""
        params = make_harvest_params()

        async def is_meta(addr: ChecksumAddress) -> bool:
            return addr == VAULT_1

        with (
            patch(f'{MODULE}.is_meta_vault', side_effect=is_meta),
            patch(
                f'{MODULE}.is_meta_vault_state_update_required',
                new=AsyncMock(return_value=False),
            ),
            patch(f'{MODULE}.harvest_meta_vault', new=AsyncMock()) as mock_harvest,
            patch(
                f'{MODULE}.get_multiple_harvest_params',
                new=AsyncMock(return_value={VAULT_2: params}),
            ) as mock_params,
            patch(f'{MODULE}._submit_update_vault_state', new=AsyncMock()) as mock_submit,
        ):
            await update_vaults_state(vaults=[VAULT_1, VAULT_2], block_number=BlockNumber(100))

        mock_harvest.assert_awaited_once_with(VAULT_1)
        mock_params.assert_awaited_once_with([VAULT_2], BlockNumber(100))
        mock_submit.assert_awaited_once_with(vault=VAULT_2, harvest_params=params)


class TestRedeemMetaVaultSubVaults:
    async def test_successful_redeem(self) -> None:
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(return_value=[SubVaultRedemption(vault=VAULT_1, assets=Wei(400))]),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(return_value='0xabc')
            await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))
        mock_redeemer.redeem_sub_vaults_assets.assert_awaited_once_with(VAULT_1, Wei(400))

    async def test_failed_redeem_aborts_sequence(self) -> None:
        """A failure stops the sequence; remaining entries are not attempted."""
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(
                    return_value=[
                        SubVaultRedemption(vault=VAULT_2, assets=Wei(200)),
                        SubVaultRedemption(vault=VAULT_1, assets=Wei(400)),
                    ]
                ),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(side_effect=RuntimeError('fail'))
            await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))
        mock_redeemer.redeem_sub_vaults_assets.assert_awaited_once_with(VAULT_2, Wei(200))

    async def test_nested_meta_vault_all_succeed(self) -> None:
        """Nested meta vault is redeemed before parent, in order."""
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(
                    return_value=[
                        SubVaultRedemption(vault=VAULT_2, assets=Wei(200)),
                        SubVaultRedemption(vault=VAULT_1, assets=Wei(400)),
                    ]
                ),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(return_value='0xabc')
            await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))

        calls = mock_redeemer.redeem_sub_vaults_assets.call_args_list
        assert len(calls) == 2
        assert calls[0].args == (VAULT_2, Wei(200))
        assert calls[1].args == (VAULT_1, Wei(400))

    async def test_build_order_failure_returns_silently(self) -> None:
        """Failure to build the redeem order is logged and swallowed."""
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(side_effect=RuntimeError('boom')),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock()
            await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))
        mock_redeemer.redeem_sub_vaults_assets.assert_not_called()


class TestBuildMetaVaultRedeemOrder:
    async def test_flat_meta_vault_no_nesting(self) -> None:
        """Meta vault with only regular sub-vaults returns single entry."""
        mock_registry = AsyncMock()
        mock_registry.calculate_sub_vaults_redemptions = AsyncMock(return_value=[])

        with (
            patch(f'{MODULE}.MetaVaultContract') as mock_mv_cls,
            patch(f'{MODULE}.SubVaultsRegistryContract', return_value=mock_registry),
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)),
        ):
            mock_mv_cls.return_value.sub_vaults_registry = AsyncMock(return_value=REGISTRY_1)
            result = await _build_meta_vault_redeem_order(VAULT_1, Wei(400))

        assert result == [SubVaultRedemption(vault=VAULT_1, assets=Wei(400))]

    async def test_nested_meta_vault(self) -> None:
        """MetaVault A has sub-vault B (meta vault). Order: B first, then A."""
        redemption_b = SubVaultRedemption(vault=VAULT_2, assets=Wei(200))
        redemption_c = SubVaultRedemption(vault=VAULT_3, assets=Wei(100))

        # Registry for A returns B (meta) and C (regular)
        mock_registry_a = AsyncMock()
        mock_registry_a.calculate_sub_vaults_redemptions = AsyncMock(
            return_value=[redemption_b, redemption_c]
        )
        # Registry for B returns no nested meta vaults
        mock_registry_b = AsyncMock()
        mock_registry_b.calculate_sub_vaults_redemptions = AsyncMock(return_value=[])

        registry_a = Web3.to_checksum_address('0x' + 'aa' * 20)
        registry_b = Web3.to_checksum_address('0x' + 'bb' * 20)

        async def mock_is_meta_vault(addr: ChecksumAddress) -> bool:
            return addr in (VAULT_1, VAULT_2)

        def mock_meta_vault_contract(addr: ChecksumAddress) -> MagicMock:
            m = MagicMock()
            if addr == VAULT_1:
                m.sub_vaults_registry = AsyncMock(return_value=registry_a)
            else:
                m.sub_vaults_registry = AsyncMock(return_value=registry_b)
            return m

        def mock_registry_contract(addr: ChecksumAddress) -> AsyncMock:
            if addr == registry_a:
                return mock_registry_a
            return mock_registry_b

        with (
            patch(f'{MODULE}.MetaVaultContract', side_effect=mock_meta_vault_contract),
            patch(f'{MODULE}.SubVaultsRegistryContract', side_effect=mock_registry_contract),
            patch(f'{MODULE}.is_meta_vault', side_effect=mock_is_meta_vault),
        ):
            result = await _build_meta_vault_redeem_order(VAULT_1, Wei(400))

        assert result == [
            SubVaultRedemption(vault=VAULT_2, assets=Wei(200)),
            SubVaultRedemption(vault=VAULT_1, assets=Wei(400)),
        ]

    async def test_skips_zero_asset_redemptions(self) -> None:
        """Sub-vaults with zero assets are not recursed into."""
        redemption = SubVaultRedemption(vault=VAULT_2, assets=Wei(0))
        mock_registry = AsyncMock()
        mock_registry.calculate_sub_vaults_redemptions = AsyncMock(return_value=[redemption])

        with (
            patch(f'{MODULE}.MetaVaultContract') as mock_mv_cls,
            patch(f'{MODULE}.SubVaultsRegistryContract', return_value=mock_registry),
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
        ):
            mock_mv_cls.return_value.sub_vaults_registry = AsyncMock(return_value=REGISTRY_1)
            result = await _build_meta_vault_redeem_order(VAULT_1, Wei(400))

        assert result == [SubVaultRedemption(vault=VAULT_1, assets=Wei(400))]


class TestProcessExitQueue:
    async def test_cannot_process(self) -> None:
        with patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer:
            mock_redeemer.can_process_exit_queue = AsyncMock(return_value=False)
            await _process_exit_queue(BlockNumber(100))
            mock_redeemer.process_exit_queue.assert_not_called()

    @pytest.mark.parametrize('tx_status', [1, 0])
    async def test_process_exit_queue(self, tx_status: int) -> None:
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': tx_status})
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.execution_client', new=mock_client),
            patch(f'{MODULE}.settings') as mock_settings,
        ):
            mock_settings.execution_transaction_timeout = 120
            mock_redeemer.can_process_exit_queue = AsyncMock(return_value=True)
            mock_redeemer.process_exit_queue = AsyncMock(return_value='0xabc')
            await _process_exit_queue(BlockNumber(100))
            mock_redeemer.process_exit_queue.assert_called_once()


class TestStartupCheck:
    async def test_authorized(self) -> None:
        wallet_address = faker.eth_address()
        mock_wallet = MagicMock()
        mock_wallet.account.address = wallet_address
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.wallet', new=mock_wallet),
        ):
            mock_redeemer.positions_manager = AsyncMock(return_value=wallet_address)
            await _startup_check()

    async def test_unauthorized(self) -> None:
        mock_wallet = MagicMock()
        mock_wallet.account.address = faker.eth_address()
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.wallet', new=mock_wallet),
        ):
            mock_redeemer.positions_manager = AsyncMock(return_value=faker.eth_address())
            with pytest.raises(RuntimeError, match='Position Manager role must be assigned'):
                await _startup_check()


class TestSubmitUpdateVaultState:
    async def test_successful(self) -> None:
        params = make_harvest_params()
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 1})

        tx_mock = AsyncMock(return_value=b'\x01' * 32)
        with (
            patch(f'{MODULE}.VaultContract') as mock_vault_cls,
            patch(f'{MODULE}.transaction_gas_wrapper', new=tx_mock),
            patch(f'{MODULE}.execution_client', new=mock_client),
            patch(f'{MODULE}.settings') as mock_settings,
        ):
            mock_settings.execution_transaction_timeout = 120
            mock_vault = MagicMock()
            mock_vault.contract.functions.updateState = MagicMock(return_value='tx_function')
            mock_vault_cls.return_value = mock_vault

            await _submit_update_vault_state(vault=VAULT_1, harvest_params=params)

        # Tx wrapper called with the encoded function
        tx_mock.assert_awaited_once()
        # Receipt was awaited
        mock_client.eth.wait_for_transaction_receipt.assert_awaited_once()

    async def test_tx_status_failure_raises(self) -> None:
        params = make_harvest_params()
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 0})

        tx_mock = AsyncMock(return_value=b'\x01' * 32)
        with (
            patch(f'{MODULE}.VaultContract') as mock_vault_cls,
            patch(f'{MODULE}.transaction_gas_wrapper', new=tx_mock),
            patch(f'{MODULE}.execution_client', new=mock_client),
            patch(f'{MODULE}.settings') as mock_settings,
        ):
            mock_settings.execution_transaction_timeout = 120
            mock_vault = MagicMock()
            mock_vault.contract.functions.updateState = MagicMock(return_value='tx_function')
            mock_vault_cls.return_value = mock_vault

            with pytest.raises(RuntimeError, match='updateState tx failed'):
                await _submit_update_vault_state(vault=VAULT_1, harvest_params=params)

    async def test_web3_exception_raises(self) -> None:
        params = make_harvest_params()
        tx_mock = AsyncMock(side_effect=Web3Exception('fail'))
        with (
            patch(f'{MODULE}.VaultContract') as mock_vault_cls,
            patch(f'{MODULE}.transaction_gas_wrapper', new=tx_mock),
        ):
            mock_vault = MagicMock()
            mock_vault.contract.functions.updateState = MagicMock(return_value='tx_function')
            mock_vault_cls.return_value = mock_vault

            with pytest.raises(RuntimeError, match='Failed updateState'):
                await _submit_update_vault_state(vault=VAULT_1, harvest_params=params)


class TestProcess:
    async def test_no_queued_shares(self) -> None:
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(0))
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(1))

    async def test_below_threshold(self) -> None:
        with _mock_process() as mocks:
            # 500 wei queued shares, threshold is 1000 Gwei
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(500))
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(1000))
            mocks['mock_redeem'].assert_not_called()

    async def test_no_eligible_positions(self) -> None:
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
            mocks['mock_redeem'].assert_not_called()

    async def test_successful_redemption(self) -> None:
        positions = [make_position(leaf_shares=1000, unprocessed_shares=500, shares_to_redeem=500)]

        with _mock_process(positions=positions) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
            mocks['mock_update_state'].assert_awaited_once()
            mocks['mock_redeem'].assert_awaited_once()


# --- Helpers ---


@contextmanager
def _mock_redeem_positions(
    withdrawable: Wei | None = None,
    get_withdrawable: AsyncMock | None = None,
    is_meta_vault: bool = False,
    tx_status: int = 1,
    tx_side_effects: list[bytes | Exception] | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for redeem_positions tests.

    ``withdrawable`` sets a constant return for get_withdrawable_assets; pass
    ``get_withdrawable`` to override with an explicit AsyncMock.
    """
    if get_withdrawable is None:
        get_withdrawable = AsyncMock(
            return_value=withdrawable if withdrawable is not None else Wei(0)
        )

    mock_client = AsyncMock()
    mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': tx_status})

    if tx_side_effects is not None:
        tx_mock = AsyncMock(side_effect=tx_side_effects)
    else:
        tx_mock = AsyncMock(return_value=b'\x01' * 32)

    tx_calls: list = []

    def capture_redeem_call(*args: object, **kwargs: object) -> str:
        tx_calls.append(args)
        return 'tx_function'

    with (
        patch(f'{MODULE}.get_withdrawable_assets', new=get_withdrawable),
        patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=is_meta_vault)),
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(f'{MODULE}.transaction_gas_wrapper', new=tx_mock),
        patch(f'{MODULE}.execution_client', new=mock_client),
        patch(f'{MODULE}.settings') as mock_settings,
    ):
        mock_settings.execution_transaction_timeout = 120
        mock_redeemer.contract.functions.redeemOsTokenPositions = MagicMock(
            side_effect=capture_redeem_call
        )
        yield {
            'tx_mock': tx_mock,
            'tx_calls': tx_calls,
            'mock_redeemer': mock_redeemer,
        }


def _captured_positions_arg(mocks: dict[str, MagicMock]) -> list:
    """Return the positions list from the first redeemOsTokenPositions call."""
    return mocks['tx_calls'][0][0]


@contextmanager
def _mock_process(
    positions: list[OsTokenPosition] | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Common mock setup for process() tests."""
    positions = positions or []
    mock_client = MagicMock()
    block_number_future: asyncio.Future[BlockNumber] = asyncio.Future()
    block_number_future.set_result(BlockNumber(101))
    mock_client.eth.block_number = block_number_future

    with (
        patch(f'{MODULE}.check_gas_price', new=AsyncMock(return_value=True)),
        patch(f'{MODULE}._process_exit_queue', new=AsyncMock()),
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(
            f'{MODULE}.create_os_token_converter',
            new=AsyncMock(return_value=make_converter()),
        ),
        patch(f'{MODULE}.settings') as mock_settings,
        patch(
            f'{MODULE}.fetch_positions_from_ipfs',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.calculate_redeemable_shares',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.update_vaults_state',
            new=AsyncMock(),
        ) as mock_update_state,
        patch(
            f'{MODULE}.redeem_positions',
            new=AsyncMock(),
        ) as mock_redeem,
        patch(f'{MODULE}.execution_client', new=mock_client),
    ):
        mock_settings.network_config.VAULT_BALANCE_SYMBOL = 'ETH'
        yield {
            'mock_redeemer': mock_redeemer,
            'mock_redeem': mock_redeem,
            'mock_update_state': mock_update_state,
        }


def make_converter(total_assets: int = 110, total_shares: int = 100) -> OsTokenConverter:
    return OsTokenConverter(Wei(total_assets), Wei(total_shares))


def make_position(
    vault: ChecksumAddress = VAULT_1,
    owner: ChecksumAddress = OWNER_1,
    leaf_shares: int = 1000,
    unprocessed_shares: int = 0,
    shares_to_redeem: int = 0,
) -> OsTokenPosition:
    return OsTokenPosition(
        vault=vault,
        owner=owner,
        leaf_shares=Wei(leaf_shares),
        unprocessed_shares=Wei(unprocessed_shares),
        shares_to_redeem=Wei(shares_to_redeem),
    )


def make_harvest_params() -> HarvestParams:
    return HarvestParams(
        rewards_root=HexBytes(b'\x01' * 32),
        reward=Wei(100),
        unlocked_mev_reward=Wei(50),
        proof=[HexBytes(b'\x02' * 32)],
    )
