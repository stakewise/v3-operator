import asyncio
from contextlib import contextmanager
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from hexbytes import HexBytes
from sw_utils.tests import faker
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Gwei, Wei

from src.commands.internal.process_redeemer import (
    _build_meta_vault_redeem_order,
    _process_exit_queue,
    _startup_check,
    _try_redeem_meta_vault,
    build_multi_proof,
    calculate_redeemable_shares,
    execute_redemption,
    fetch_positions_from_ipfs,
    process,
    select_positions,
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
        result = build_multi_proof(
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

        result = build_multi_proof(
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

        result = build_multi_proof(
            tree_nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1, pos2],
        )
        assert len(result.leaves) == 2


class TestSelectPositions:
    async def test_empty_positions(self) -> None:
        positions_to_redeem = await select_positions(
            os_token_positions=[],
            queued_shares=10000,
            converter=make_converter(),
            vault_to_harvest_params={},
            vault_to_withdrawable_assets={},
            skip_harvest=False,
        )
        assert positions_to_redeem == []

    async def test_single_position_sufficient_assets(self) -> None:
        position = make_position(unprocessed_shares=500)

        positions_to_redeem = await select_positions(
            os_token_positions=[position],
            queued_shares=10000,
            converter=make_converter(),
            vault_to_harvest_params={VAULT_1: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(1000)},
            skip_harvest=False,
        )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].shares_to_redeem == Wei(500)

    async def test_single_position_insufficient_assets_partial_fill(self) -> None:
        position = make_position(unprocessed_shares=500)

        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            positions_to_redeem = await select_positions(
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                vault_to_harvest_params={VAULT_1: None},
                vault_to_withdrawable_assets={VAULT_1: Wei(100)},
                skip_harvest=False,
            )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].shares_to_redeem == Wei(100)

    async def test_single_position_zero_withdrawable(self) -> None:
        position = make_position(unprocessed_shares=500)

        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            positions_to_redeem = await select_positions(
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                vault_to_harvest_params={VAULT_1: None},
                vault_to_withdrawable_assets={VAULT_1: Wei(0)},
                skip_harvest=False,
            )
        assert positions_to_redeem == []

    async def test_queued_shares_limits_redemption(self) -> None:
        position = make_position(unprocessed_shares=500)

        positions_to_redeem = await select_positions(
            os_token_positions=[position],
            queued_shares=200,
            converter=make_converter(),
            vault_to_harvest_params={VAULT_1: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
            skip_harvest=False,
        )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].shares_to_redeem == Wei(200)

    async def test_multiple_positions_limited_by_withdrawable_assets(self) -> None:
        pos1 = make_position(owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(owner=OWNER_2, unprocessed_shares=1000)

        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            positions_to_redeem = await select_positions(
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                vault_to_harvest_params={VAULT_1: None},
                vault_to_withdrawable_assets={VAULT_1: Wei(700)},
                skip_harvest=False,
            )
        assert len(positions_to_redeem) == 2
        assert positions_to_redeem[0].owner == OWNER_1
        assert positions_to_redeem[0].shares_to_redeem == Wei(500)
        assert positions_to_redeem[1].owner == OWNER_2
        assert positions_to_redeem[1].shares_to_redeem == Wei(200)

    async def test_multiple_vaults_both_selected(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=800)

        positions_to_redeem = await select_positions(
            os_token_positions=[pos1, pos2],
            queued_shares=10000,
            converter=make_converter(100, 100),
            vault_to_harvest_params={VAULT_1: None, VAULT_2: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000), VAULT_2: Wei(10000)},
            skip_harvest=False,
        )
        assert len(positions_to_redeem) == 2

    async def test_stops_across_vaults_when_queued_shares_exhausted(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=800)

        positions_to_redeem = await select_positions(
            os_token_positions=[pos1, pos2],
            queued_shares=500,
            converter=make_converter(100, 100),
            vault_to_harvest_params={VAULT_1: None, VAULT_2: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000), VAULT_2: Wei(10000)},
            skip_harvest=False,
        )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].vault == VAULT_1

    async def test_preserves_original_amount(self) -> None:
        pos = make_position(leaf_shares=1000, unprocessed_shares=500)

        positions_to_redeem = await select_positions(
            os_token_positions=[pos],
            queued_shares=200,
            converter=make_converter(),
            vault_to_harvest_params={VAULT_1: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
            skip_harvest=False,
        )
        assert positions_to_redeem[0].leaf_shares == Wei(1000)
        assert positions_to_redeem[0].shares_to_redeem == Wei(200)

    async def test_stops_within_vault_when_queued_shares_exhausted(self) -> None:
        pos1 = make_position(owner=OWNER_1, unprocessed_shares=400)
        pos2 = make_position(owner=OWNER_2, unprocessed_shares=300)

        positions_to_redeem = await select_positions(
            os_token_positions=[pos1, pos2],
            queued_shares=400,
            converter=make_converter(100, 100),
            vault_to_harvest_params={VAULT_1: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
            skip_harvest=False,
        )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].owner == OWNER_1

    async def test_partial_fills_first_then_exhausts_withdrawable(self) -> None:
        pos1 = make_position(owner=OWNER_1, unprocessed_shares=1000)
        pos2 = make_position(owner=OWNER_2, unprocessed_shares=100)

        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            positions_to_redeem = await select_positions(
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                vault_to_harvest_params={VAULT_1: None},
                vault_to_withdrawable_assets={VAULT_1: Wei(500)},
                skip_harvest=False,
            )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].owner == OWNER_1
        assert positions_to_redeem[0].shares_to_redeem == Wei(500)


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


class TestTryRedeemMetaVault:
    async def test_not_meta_vault(self) -> None:
        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            result = await _try_redeem_meta_vault(
                vault_address=VAULT_1,
                assets=Wei(400),
                current_withdrawable=Wei(100),
                harvest_params=None,
                skip_harvest=False,
            )
        assert result == Wei(100)

    async def test_meta_vault_successful_redeem(self) -> None:
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(f'{MODULE}.is_meta_vault_harvested', new=AsyncMock(return_value=True)),
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(return_value=[SubVaultRedemption(vault=VAULT_1, assets=Wei(400))]),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(
                f'{MODULE}.get_withdrawable_assets',
                new=AsyncMock(return_value=Wei(600)),
            ),
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(return_value='0xabc')
            result = await _try_redeem_meta_vault(
                vault_address=VAULT_1,
                assets=Wei(400),
                current_withdrawable=Wei(100),
                harvest_params=None,
                skip_harvest=False,
            )
        assert result == Wei(600)
        mock_redeemer.redeem_sub_vaults_assets.assert_called_once_with(VAULT_1, Wei(400))

    async def test_meta_vault_failed_redeem(self) -> None:
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(f'{MODULE}.is_meta_vault_harvested', new=AsyncMock(return_value=True)),
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(return_value=[SubVaultRedemption(vault=VAULT_1, assets=Wei(400))]),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(side_effect=RuntimeError('fail'))
            result = await _try_redeem_meta_vault(
                vault_address=VAULT_1,
                assets=Wei(400),
                current_withdrawable=Wei(100),
                harvest_params=None,
                skip_harvest=False,
            )
        assert result == Wei(100)

    async def test_nested_meta_vault_all_succeed(self) -> None:
        """Nested meta vault B is redeemed before parent A."""
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(f'{MODULE}.is_meta_vault_harvested', new=AsyncMock(return_value=True)),
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
            patch(
                f'{MODULE}.get_withdrawable_assets',
                new=AsyncMock(return_value=Wei(500)),
            ),
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(return_value='0xabc')
            result = await _try_redeem_meta_vault(
                vault_address=VAULT_1,
                assets=Wei(400),
                current_withdrawable=Wei(100),
                harvest_params=None,
                skip_harvest=False,
            )
        assert result == Wei(500)
        calls = mock_redeemer.redeem_sub_vaults_assets.call_args_list
        assert len(calls) == 2
        assert calls[0].args == (VAULT_2, Wei(200))
        assert calls[1].args == (VAULT_1, Wei(400))

    async def test_nested_meta_vault_nested_fails(self) -> None:
        """If nested redemption fails, returns current_withdrawable."""
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(f'{MODULE}.is_meta_vault_harvested', new=AsyncMock(return_value=True)),
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
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(
                side_effect=RuntimeError('nested fail')
            )
            result = await _try_redeem_meta_vault(
                vault_address=VAULT_1,
                assets=Wei(400),
                current_withdrawable=Wei(100),
                harvest_params=None,
                skip_harvest=False,
            )
        assert result == Wei(100)
        # Only the first call (nested vault) was attempted
        mock_redeemer.redeem_sub_vaults_assets.assert_called_once_with(VAULT_2, Wei(200))


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


class TestExecuteRedemption:
    async def test_successful_with_harvest_params(self) -> None:
        pos = make_position(
            vault=VAULT_1, leaf_shares=1000, unprocessed_shares=500, shares_to_redeem=500
        )
        harvest_params = make_harvest_params()

        with _mock_execute_redemption(tx_status=1) as mocks:
            result = await execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: harvest_params},
                nonce=5,
            )

        assert result is not None
        # Verify encode_abi was called for updateVaultState and redeemOsTokenPositions
        encode_calls = mocks['mock_redeemer'].encode_abi.call_args_list
        assert any(
            c.kwargs.get('fn_name') == 'updateVaultState'
            or (c.args and c.args[0] == 'updateVaultState')
            for c in encode_calls
            if c.kwargs.get('fn_name') or c.args
        )

    async def test_successful_without_harvest_params(self) -> None:
        pos = make_position(
            vault=VAULT_1, leaf_shares=1000, unprocessed_shares=500, shares_to_redeem=500
        )

        with _mock_execute_redemption(tx_status=1):
            result = await execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                nonce=5,
            )

        assert result is not None

    async def test_web3_exception(self) -> None:
        pos = make_position(leaf_shares=1000, unprocessed_shares=500, shares_to_redeem=500)

        with _mock_execute_redemption(tx_side_effect=Web3Exception('fail')):
            result = await execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                nonce=5,
            )

        assert result is None

    async def test_tx_receipt_fails(self) -> None:
        pos = make_position(leaf_shares=1000, unprocessed_shares=500, shares_to_redeem=500)

        with _mock_execute_redemption(tx_status=0):
            result = await execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                nonce=5,
            )

        assert result is None


class TestProcess:
    async def test_no_queued_shares(self) -> None:
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(0))
            await process(
                block_number=BlockNumber(100), min_queued_assets=Gwei(1), skip_harvest=False
            )

    async def test_below_threshold(self) -> None:
        with _mock_process() as mocks:
            # 500 wei queued shares, threshold is 1000 Gwei
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(500))
            await process(
                block_number=BlockNumber(100),
                min_queued_assets=Gwei(1000),
                skip_harvest=False,
            )
            mocks['mock_execute'].assert_not_called()

    async def test_no_eligible_positions(self) -> None:
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(
                block_number=BlockNumber(100), min_queued_assets=Gwei(0), skip_harvest=False
            )
            mocks['mock_execute'].assert_not_called()

    async def test_successful_redemption(self) -> None:
        positions = [make_position(leaf_shares=1000, unprocessed_shares=500, shares_to_redeem=500)]

        with _mock_process(positions=positions) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(
                block_number=BlockNumber(100), min_queued_assets=Gwei(0), skip_harvest=False
            )
            mocks['mock_execute'].assert_called_once()


# --- Helpers ---


@contextmanager
def _mock_execute_redemption(
    tx_status: int = 1,
    tx_side_effect: Exception | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Common mock setup for execute_redemption tests."""
    mock_client = AsyncMock()
    mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': tx_status})

    tx_mock = AsyncMock(
        return_value=b'\x01' * 32,
        side_effect=tx_side_effect,
    )

    with (
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(f'{MODULE}.transaction_gas_wrapper', new=tx_mock),
        patch(f'{MODULE}.execution_client', new=mock_client),
        patch(f'{MODULE}.settings') as mock_settings,
    ):
        mock_settings.execution_transaction_timeout = 120
        mock_redeemer.encode_abi.return_value = HexStr('0xencoded')
        yield {
            'mock_redeemer': mock_redeemer,
        }


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
            f'{MODULE}.get_multiple_harvest_params',
            new=AsyncMock(return_value={VAULT_1: None}),
        ),
        patch(
            f'{MODULE}.get_withdrawable_assets',
            new=AsyncMock(return_value=Wei(10000)),
        ),
        patch(
            f'{MODULE}.select_positions',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.execute_redemption',
            new=AsyncMock(return_value='0xtxhash'),
        ) as mock_execute,
        patch(f'{MODULE}.execution_client', new=mock_client),
    ):
        mock_settings.network_config.VAULT_BALANCE_SYMBOL = 'ETH'
        yield {
            'mock_redeemer': mock_redeemer,
            'mock_execute': mock_execute,
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
