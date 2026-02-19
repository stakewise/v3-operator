from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from hexbytes import HexBytes
from sw_utils.tests import faker
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Wei

from src.commands.internal.process_redeemer import (
    PositionSelectionResult,
    _execute_redemption,
    _fetch_redeemable_positions,
    _filter_positions_to_redeem,
    _get_multi_proof,
    _process_exit_queue,
    _select_positions_to_redeem,
    _startup_check,
    _try_redeem_sub_vaults,
    process,
)
from src.common.typings import HarvestParams
from src.redemptions.os_token_converter import OsTokenConverter
from src.redemptions.tasks import ZERO_MERKLE_ROOT
from src.redemptions.typings import OsTokenPosition, RedeemablePositions

MODULE = 'src.commands.internal.process_redeemer'

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
VAULT_2 = Web3.to_checksum_address('0x' + '22' * 20)
OWNER_1 = Web3.to_checksum_address('0x' + '33' * 20)
OWNER_2 = Web3.to_checksum_address('0x' + '44' * 20)


# --- Pure function tests (no mocks) ---


class TestGetMultiProof:
    def test_single_position(self) -> None:
        position = make_position(amount=1000, available_shares=500)
        result = _get_multi_proof(
            tree_nonce=5,
            all_positions=[position],
            positions_to_redeem=[position],
        )
        assert len(result.leaves) == 1

    def test_partial_redeem(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, amount=1000, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, amount=2000, available_shares=1000)

        result = _get_multi_proof(
            tree_nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1],
        )
        assert len(result.leaves) == 1
        assert len(result.proof) > 0

    def test_all_positions_redeemed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, amount=1000, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, amount=2000, available_shares=1000)

        result = _get_multi_proof(
            tree_nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1, pos2],
        )
        assert len(result.leaves) == 2


class TestFilterPositionsToRedeem:
    def test_empty_positions(self) -> None:
        result = _filter_positions_to_redeem(
            vault_to_positions={},
            vault_to_withdrawable_assets={},
            vault_to_harvest_params={},
            queued_shares=1000,
            os_token_converter=make_converter(),
        )
        assert result.positions_to_redeem == []
        assert result.vault_to_harvest_params == {}

    def test_single_position_sufficient_assets(self) -> None:
        position = make_position(available_shares=500)
        # to_assets(500) = 500 * 110 / 100 = 550; withdrawable=1000 → selected
        result = _filter_positions_to_redeem(
            vault_to_positions={VAULT_1: [position]},
            vault_to_withdrawable_assets={VAULT_1: Wei(1000)},
            vault_to_harvest_params={VAULT_1: None},
            queued_shares=10000,
            os_token_converter=make_converter(),
        )
        assert len(result.positions_to_redeem) == 1
        assert result.positions_to_redeem[0].shares_to_redeem == Wei(500)

    def test_single_position_insufficient_assets(self) -> None:
        position = make_position(available_shares=500)
        # to_assets(500) = 550; withdrawable=100 → skipped
        result = _filter_positions_to_redeem(
            vault_to_positions={VAULT_1: [position]},
            vault_to_withdrawable_assets={VAULT_1: Wei(100)},
            vault_to_harvest_params={VAULT_1: None},
            queued_shares=10000,
            os_token_converter=make_converter(),
        )
        assert result.positions_to_redeem == []

    def test_queued_shares_limits_redemption(self) -> None:
        position = make_position(available_shares=500)
        result = _filter_positions_to_redeem(
            vault_to_positions={VAULT_1: [position]},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
            vault_to_harvest_params={VAULT_1: None},
            queued_shares=200,
            os_token_converter=make_converter(),
        )
        assert len(result.positions_to_redeem) == 1
        assert result.positions_to_redeem[0].shares_to_redeem == Wei(200)

    def test_multiple_positions_limited_by_withdrawable_assets(self) -> None:
        pos1 = make_position(owner=OWNER_1, available_shares=500)
        pos2 = make_position(owner=OWNER_2, available_shares=1000)
        # 1:1 converter; pos1=500 assets, pos2=1000 assets; withdrawable=700
        # pos1 fits (700-500=200 remaining), pos2 doesn't (1000>200)
        result = _filter_positions_to_redeem(
            vault_to_positions={VAULT_1: [pos1, pos2]},
            vault_to_withdrawable_assets={VAULT_1: Wei(700)},
            vault_to_harvest_params={VAULT_1: None},
            queued_shares=10000,
            os_token_converter=make_converter(100, 100),
        )
        assert len(result.positions_to_redeem) == 1
        assert result.positions_to_redeem[0].owner == OWNER_1

    def test_multiple_vaults_both_selected(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, available_shares=800)

        vault_to_positions: dict[ChecksumAddress, list[OsTokenPosition]] = {}
        vault_to_positions[VAULT_1] = [pos1]
        vault_to_positions[VAULT_2] = [pos2]

        result = _filter_positions_to_redeem(
            vault_to_positions=vault_to_positions,
            vault_to_withdrawable_assets={VAULT_1: Wei(10000), VAULT_2: Wei(10000)},
            vault_to_harvest_params={VAULT_1: None, VAULT_2: None},
            queued_shares=10000,
            os_token_converter=make_converter(100, 100),
        )
        assert len(result.positions_to_redeem) == 2

    def test_stops_across_vaults_when_queued_shares_exhausted(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, available_shares=800)

        vault_to_positions: dict[ChecksumAddress, list[OsTokenPosition]] = {}
        vault_to_positions[VAULT_1] = [pos1]
        vault_to_positions[VAULT_2] = [pos2]

        result = _filter_positions_to_redeem(
            vault_to_positions=vault_to_positions,
            vault_to_withdrawable_assets={VAULT_1: Wei(10000), VAULT_2: Wei(10000)},
            vault_to_harvest_params={VAULT_1: None, VAULT_2: None},
            queued_shares=500,
            os_token_converter=make_converter(100, 100),
        )
        assert len(result.positions_to_redeem) == 1
        assert result.positions_to_redeem[0].vault == VAULT_1

    def test_preserves_harvest_params(self) -> None:
        pos = make_position(available_shares=500)
        harvest_params = make_harvest_params()

        result = _filter_positions_to_redeem(
            vault_to_positions={VAULT_1: [pos]},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
            vault_to_harvest_params={VAULT_1: harvest_params},
            queued_shares=10000,
            os_token_converter=make_converter(),
        )
        assert result.vault_to_harvest_params[VAULT_1] is harvest_params

    def test_preserves_original_amount(self) -> None:
        pos = make_position(amount=1000, available_shares=500)
        result = _filter_positions_to_redeem(
            vault_to_positions={VAULT_1: [pos]},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
            vault_to_harvest_params={VAULT_1: None},
            queued_shares=200,
            os_token_converter=make_converter(),
        )
        assert result.positions_to_redeem[0].amount == Wei(1000)
        assert result.positions_to_redeem[0].shares_to_redeem == Wei(200)

    def test_stops_within_vault_when_queued_shares_exhausted(self) -> None:
        # Multiple positions in same vault, queued_shares runs out mid-vault
        pos1 = make_position(owner=OWNER_1, available_shares=400)
        pos2 = make_position(owner=OWNER_2, available_shares=300)
        # 1:1 converter; pos1 consumes all 400 queued_shares, pos2 is skipped
        result = _filter_positions_to_redeem(
            vault_to_positions={VAULT_1: [pos1, pos2]},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
            vault_to_harvest_params={VAULT_1: None},
            queued_shares=400,
            os_token_converter=make_converter(100, 100),
        )
        assert len(result.positions_to_redeem) == 1
        assert result.positions_to_redeem[0].owner == OWNER_1

    def test_skips_position_then_selects_next(self) -> None:
        # First position too expensive, second fits
        pos1 = make_position(owner=OWNER_1, available_shares=1000)
        pos2 = make_position(owner=OWNER_2, available_shares=100)
        # 1:1 converter; pos1=1000 assets > 500 withdrawable; pos2=100 <= 500
        result = _filter_positions_to_redeem(
            vault_to_positions={VAULT_1: [pos1, pos2]},
            vault_to_withdrawable_assets={VAULT_1: Wei(500)},
            vault_to_harvest_params={VAULT_1: None},
            queued_shares=10000,
            os_token_converter=make_converter(100, 100),
        )
        assert len(result.positions_to_redeem) == 1
        assert result.positions_to_redeem[0].owner == OWNER_2


# --- Async function tests (with mocks) ---


class TestFetchRedeemablePositions:
    async def test_empty_positions(self) -> None:
        async def empty_gen(block_number: BlockNumber | None = None):  # type: ignore[misc]
            return
            yield  # noqa: unreachable

        with (
            patch(f'{MODULE}.iter_os_token_positions', side_effect=empty_gen),
            patch(f'{MODULE}.get_processed_shares_batch', new=AsyncMock(return_value=[])),
        ):
            result = await _fetch_redeemable_positions(tree_nonce=5, block_number=BlockNumber(100))
        assert result == []

    async def test_all_shares_processed(self) -> None:
        pos = make_position(amount=1000)

        async def gen(block_number: BlockNumber | None = None):  # type: ignore[misc]
            yield pos

        with (
            patch(f'{MODULE}.iter_os_token_positions', side_effect=gen),
            patch(
                f'{MODULE}.get_processed_shares_batch',
                new=AsyncMock(return_value=[Wei(1000)]),
            ),
        ):
            result = await _fetch_redeemable_positions(tree_nonce=5, block_number=BlockNumber(100))
        assert result == []

    async def test_partial_processed_shares(self) -> None:
        pos = make_position(amount=1000)

        async def gen(block_number: BlockNumber | None = None):  # type: ignore[misc]
            yield pos

        with (
            patch(f'{MODULE}.iter_os_token_positions', side_effect=gen),
            patch(
                f'{MODULE}.get_processed_shares_batch',
                new=AsyncMock(return_value=[Wei(300)]),
            ),
        ):
            result = await _fetch_redeemable_positions(tree_nonce=5, block_number=BlockNumber(100))
        assert len(result) == 1
        assert result[0].available_shares == Wei(700)
        assert result[0].amount == Wei(1000)

    async def test_multiple_positions_mixed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, amount=1000)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, amount=2000)

        async def gen(block_number: BlockNumber | None = None):  # type: ignore[misc]
            yield pos1
            yield pos2

        # pos1 fully processed, pos2 partially processed
        with (
            patch(f'{MODULE}.iter_os_token_positions', side_effect=gen),
            patch(
                f'{MODULE}.get_processed_shares_batch',
                new=AsyncMock(return_value=[Wei(1000), Wei(500)]),
            ),
        ):
            result = await _fetch_redeemable_positions(tree_nonce=5, block_number=BlockNumber(100))
        assert len(result) == 1
        assert result[0].owner == OWNER_2
        assert result[0].available_shares == Wei(1500)


class TestTryRedeemSubVaults:
    async def test_sufficient_withdrawable_assets(self) -> None:
        positions = [make_position(available_shares=500)]
        # 1:1 converter; vault_positions_assets=500 <= withdrawable=1000 → return
        result = await _try_redeem_sub_vaults(
            vault_address=VAULT_1,
            positions=positions,
            withdrawable_assets=Wei(1000),
            harvest_params=None,
            os_token_converter=make_converter(100, 100),
        )
        assert result == Wei(1000)

    async def test_insufficient_non_meta_vault(self) -> None:
        positions = [make_position(available_shares=500)]
        # vault_positions_assets=500 > withdrawable=100, but not meta-vault
        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            result = await _try_redeem_sub_vaults(
                vault_address=VAULT_1,
                positions=positions,
                withdrawable_assets=Wei(100),
                harvest_params=None,
                os_token_converter=make_converter(100, 100),
            )
        assert result == Wei(100)

    async def test_meta_vault_successful_redeem(self) -> None:
        positions = [make_position(available_shares=500)]
        # vault_positions_assets=500 > withdrawable=100, meta-vault
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(
                f'{MODULE}.get_withdrawable_assets',
                new=AsyncMock(return_value=Wei(600)),
            ),
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(return_value='0xabc')
            result = await _try_redeem_sub_vaults(
                vault_address=VAULT_1,
                positions=positions,
                withdrawable_assets=Wei(100),
                harvest_params=None,
                os_token_converter=make_converter(100, 100),
            )
        assert result == Wei(600)
        mock_redeemer.redeem_sub_vaults_assets.assert_called_once_with(VAULT_1, Wei(400))

    async def test_meta_vault_failed_redeem(self) -> None:
        positions = [make_position(available_shares=500)]
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(side_effect=RuntimeError('fail'))
            result = await _try_redeem_sub_vaults(
                vault_address=VAULT_1,
                positions=positions,
                withdrawable_assets=Wei(100),
                harvest_params=None,
                os_token_converter=make_converter(100, 100),
            )
        assert result == Wei(100)


class TestProcessExitQueue:
    async def test_cannot_process(self) -> None:
        with patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer:
            mock_redeemer.can_process_exit_queue = AsyncMock(return_value=False)
            await _process_exit_queue(BlockNumber(100))
            mock_redeemer.process_exit_queue.assert_not_called()

    async def test_process_success(self) -> None:
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 1})
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

    async def test_process_tx_fails(self) -> None:
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 0})
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.execution_client', new=mock_client),
            patch(f'{MODULE}.settings') as mock_settings,
        ):
            mock_settings.execution_transaction_timeout = 120
            mock_redeemer.can_process_exit_queue = AsyncMock(return_value=True)
            mock_redeemer.process_exit_queue = AsyncMock(return_value='0xabc')
            # Should not raise, just log error
            await _process_exit_queue(BlockNumber(100))


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


class TestSelectPositionsToRedeem:
    async def test_empty_positions(self) -> None:
        result = await _select_positions_to_redeem(
            redeemable_positions=[],
            queued_shares=10000,
            os_token_converter=make_converter(),
            block_number=BlockNumber(100),
        )
        assert result.positions_to_redeem == []

    async def test_calls_io_per_vault(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, amount=1000, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, amount=2000, available_shares=800)

        mock_harvest = AsyncMock(return_value=None)
        mock_withdrawable = AsyncMock(return_value=Wei(10000))
        mock_sub_vaults = AsyncMock(return_value=Wei(10000))

        with (
            patch(f'{MODULE}.get_harvest_params', mock_harvest),
            patch(f'{MODULE}.get_withdrawable_assets', mock_withdrawable),
            patch(f'{MODULE}._try_redeem_sub_vaults', mock_sub_vaults),
        ):
            result = await _select_positions_to_redeem(
                redeemable_positions=[pos1, pos2],
                queued_shares=10000,
                os_token_converter=make_converter(100, 100),
                block_number=BlockNumber(100),
            )

        assert mock_harvest.call_count == 2
        assert mock_withdrawable.call_count == 2
        assert mock_sub_vaults.call_count == 2
        assert len(result.positions_to_redeem) == 2

    async def test_passes_harvest_params_to_get_withdrawable_assets(self) -> None:
        pos = make_position(vault=VAULT_1, available_shares=500)
        harvest_params = make_harvest_params()

        mock_harvest = AsyncMock(return_value=harvest_params)
        mock_withdrawable = AsyncMock(return_value=Wei(10000))
        mock_sub_vaults = AsyncMock(return_value=Wei(10000))

        with (
            patch(f'{MODULE}.get_harvest_params', mock_harvest),
            patch(f'{MODULE}.get_withdrawable_assets', mock_withdrawable),
            patch(f'{MODULE}._try_redeem_sub_vaults', mock_sub_vaults),
        ):
            result = await _select_positions_to_redeem(
                redeemable_positions=[pos],
                queued_shares=10000,
                os_token_converter=make_converter(100, 100),
                block_number=BlockNumber(100),
            )

        mock_withdrawable.assert_called_once_with(VAULT_1, harvest_params)
        assert result.vault_to_harvest_params[VAULT_1] is harvest_params


class TestExecuteRedemption:
    async def test_successful_with_harvest_params(self) -> None:
        pos = make_position(vault=VAULT_1, amount=1000, available_shares=500, shares_to_redeem=500)
        harvest_params = make_harvest_params()
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 1})

        with (
            patch(f'{MODULE}.VaultContract') as MockVaultContract,
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.multicall_contract'),
            patch(
                f'{MODULE}.transaction_gas_wrapper',
                new=AsyncMock(return_value=b'\x01' * 32),
            ),
            patch(f'{MODULE}.execution_client', new=mock_client),
            patch(f'{MODULE}.settings') as mock_settings,
        ):
            mock_settings.execution_transaction_timeout = 120
            mock_vault = MockVaultContract.return_value
            mock_vault.contract_address = VAULT_1
            mock_vault.get_update_state_call.return_value = HexStr('0xupdate')
            mock_redeemer.encode_abi.return_value = HexStr('0xredeem')
            mock_redeemer.contract_address = VAULT_2

            result = await _execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: harvest_params},
                tree_nonce=5,
            )

        assert result is not None
        mock_vault.get_update_state_call.assert_called_once_with(harvest_params)

    async def test_successful_without_harvest_params(self) -> None:
        pos = make_position(vault=VAULT_1, amount=1000, available_shares=500, shares_to_redeem=500)
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 1})

        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.multicall_contract'),
            patch(
                f'{MODULE}.transaction_gas_wrapper',
                new=AsyncMock(return_value=b'\x01' * 32),
            ),
            patch(f'{MODULE}.execution_client', new=mock_client),
            patch(f'{MODULE}.settings') as mock_settings,
        ):
            mock_settings.execution_transaction_timeout = 120
            mock_redeemer.encode_abi.return_value = HexStr('0xredeem')
            mock_redeemer.contract_address = VAULT_2

            result = await _execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                tree_nonce=5,
            )

        assert result is not None

    async def test_web3_exception(self) -> None:
        pos = make_position(amount=1000, available_shares=500, shares_to_redeem=500)

        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.multicall_contract'),
            patch(
                f'{MODULE}.transaction_gas_wrapper',
                new=AsyncMock(side_effect=Web3Exception('fail')),
            ),
        ):
            mock_redeemer.encode_abi.return_value = HexStr('0xredeem')
            mock_redeemer.contract_address = VAULT_2

            result = await _execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                tree_nonce=5,
            )

        assert result is None

    async def test_tx_receipt_fails(self) -> None:
        pos = make_position(amount=1000, available_shares=500, shares_to_redeem=500)
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 0})

        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.multicall_contract'),
            patch(
                f'{MODULE}.transaction_gas_wrapper',
                new=AsyncMock(return_value=b'\x01' * 32),
            ),
            patch(f'{MODULE}.execution_client', new=mock_client),
            patch(f'{MODULE}.settings') as mock_settings,
        ):
            mock_settings.execution_transaction_timeout = 120
            mock_redeemer.encode_abi.return_value = HexStr('0xredeem')
            mock_redeemer.contract_address = VAULT_2

            result = await _execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                tree_nonce=5,
            )

        assert result is None


class TestProcess:
    async def test_no_queued_shares(self) -> None:
        with (
            patch(f'{MODULE}._process_exit_queue', new=AsyncMock()),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.queued_shares = AsyncMock(return_value=Wei(0))
            await process(block_number=BlockNumber(100))

    async def test_zero_merkle_root(self) -> None:
        with (
            patch(f'{MODULE}._process_exit_queue', new=AsyncMock()),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(
                f'{MODULE}.create_os_token_converter',
                new=AsyncMock(return_value=make_converter()),
            ),
        ):
            mock_redeemer.queued_shares = AsyncMock(return_value=Wei(1000))
            mock_redeemer.nonce = AsyncMock(return_value=5)
            mock_redeemer.redeemable_positions = AsyncMock(
                return_value=RedeemablePositions(
                    merkle_root=ZERO_MERKLE_ROOT,
                    ipfs_hash='QmTest',
                )
            )
            await process(block_number=BlockNumber(100))

    async def test_empty_ipfs_hash(self) -> None:
        with (
            patch(f'{MODULE}._process_exit_queue', new=AsyncMock()),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(
                f'{MODULE}.create_os_token_converter',
                new=AsyncMock(return_value=make_converter()),
            ),
        ):
            mock_redeemer.queued_shares = AsyncMock(return_value=Wei(1000))
            mock_redeemer.nonce = AsyncMock(return_value=5)
            mock_redeemer.redeemable_positions = AsyncMock(
                return_value=RedeemablePositions(
                    merkle_root=HexStr('0x' + 'ab' * 32),
                    ipfs_hash='',
                )
            )
            await process(block_number=BlockNumber(100))

    async def test_no_eligible_positions(self) -> None:
        with (
            patch(f'{MODULE}._process_exit_queue', new=AsyncMock()),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(
                f'{MODULE}.create_os_token_converter',
                new=AsyncMock(return_value=make_converter()),
            ),
            patch(
                f'{MODULE}._fetch_redeemable_positions',
                new=AsyncMock(return_value=[]),
            ),
            patch(f'{MODULE}._execute_redemption') as mock_execute,
        ):
            mock_redeemer.queued_shares = AsyncMock(return_value=Wei(1000))
            mock_redeemer.nonce = AsyncMock(return_value=5)
            mock_redeemer.redeemable_positions = AsyncMock(
                return_value=RedeemablePositions(
                    merkle_root=HexStr('0x' + 'ab' * 32),
                    ipfs_hash='QmTest',
                )
            )
            await process(block_number=BlockNumber(100))
            mock_execute.assert_not_called()

    async def test_successful_redemption(self) -> None:
        positions = [make_position(amount=1000, available_shares=500, shares_to_redeem=500)]
        selection = PositionSelectionResult(
            positions_to_redeem=positions,
            vault_to_harvest_params={VAULT_1: None},
        )

        with (
            patch(f'{MODULE}._process_exit_queue', new=AsyncMock()),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(
                f'{MODULE}.create_os_token_converter',
                new=AsyncMock(return_value=make_converter()),
            ),
            patch(
                f'{MODULE}._fetch_redeemable_positions',
                new=AsyncMock(return_value=positions),
            ),
            patch(
                f'{MODULE}._select_positions_to_redeem',
                new=AsyncMock(return_value=selection),
            ),
            patch(
                f'{MODULE}._execute_redemption',
                new=AsyncMock(return_value='0xtxhash'),
            ) as mock_execute,
        ):
            mock_redeemer.queued_shares = AsyncMock(return_value=Wei(1000))
            mock_redeemer.nonce = AsyncMock(return_value=5)
            mock_redeemer.redeemable_positions = AsyncMock(
                return_value=RedeemablePositions(
                    merkle_root=HexStr('0x' + 'ab' * 32),
                    ipfs_hash='QmTest',
                )
            )
            await process(block_number=BlockNumber(100))
            mock_execute.assert_called_once()


def make_converter(total_assets: int = 110, total_shares: int = 100) -> OsTokenConverter:
    return OsTokenConverter(Wei(total_assets), Wei(total_shares))


def make_position(
    vault: ChecksumAddress = VAULT_1,
    owner: ChecksumAddress = OWNER_1,
    amount: int = 1000,
    available_shares: int = 0,
    shares_to_redeem: int = 0,
) -> OsTokenPosition:
    return OsTokenPosition(
        vault=vault,
        owner=owner,
        amount=Wei(amount),
        available_shares=Wei(available_shares),
        shares_to_redeem=Wei(shares_to_redeem),
    )


def make_harvest_params() -> HarvestParams:
    return HarvestParams(
        rewards_root=HexBytes(b'\x01' * 32),
        reward=Wei(100),
        unlocked_mev_reward=Wei(50),
        proof=[HexBytes(b'\x02' * 32)],
    )
