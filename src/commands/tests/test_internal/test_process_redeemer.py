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
from web3.types import Wei

from src.commands.internal.process_redeemer import (
    _process_exit_queue,
    _startup_check,
    _try_redeem_meta_vault,
    build_multi_proof,
    calculate_redeemable_shares,
    execute_redemption,
    fetch_positions_from_ipfs,
    fetch_vault_withdrawable_assets,
    process,
    select_positions,
)
from src.common.typings import HarvestParams
from src.redemptions.os_token_converter import OsTokenConverter
from src.redemptions.typings import OsTokenPosition

MODULE = 'src.commands.internal.process_redeemer'

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
VAULT_2 = Web3.to_checksum_address('0x' + '22' * 20)
OWNER_1 = Web3.to_checksum_address('0x' + '33' * 20)
OWNER_2 = Web3.to_checksum_address('0x' + '44' * 20)


# --- Pure function tests (no mocks) ---


class TestBuildMultiProof:
    def test_single_position(self) -> None:
        position = make_position(amount=1000, available_shares=500)
        result = build_multi_proof(
            tree_nonce=5,
            all_positions=[position],
            positions_to_redeem=[position],
        )
        assert len(result.leaves) == 1

    def test_partial_redeem(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, amount=1000, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, amount=2000, available_shares=1000)

        result = build_multi_proof(
            tree_nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1],
        )
        assert len(result.leaves) == 1
        assert len(result.proof) > 0

    def test_all_positions_redeemed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, amount=1000, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, amount=2000, available_shares=1000)

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
        )
        assert positions_to_redeem == []

    async def test_single_position_sufficient_assets(self) -> None:
        position = make_position(available_shares=500)

        positions_to_redeem = await select_positions(
            os_token_positions=[position],
            queued_shares=10000,
            converter=make_converter(),
            vault_to_harvest_params={VAULT_1: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(1000)},
        )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].shares_to_redeem == Wei(500)

    async def test_single_position_insufficient_assets_partial_fill(self) -> None:
        position = make_position(available_shares=500)

        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            positions_to_redeem = await select_positions(
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                vault_to_harvest_params={VAULT_1: None},
                vault_to_withdrawable_assets={VAULT_1: Wei(100)},
            )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].shares_to_redeem == Wei(100)

    async def test_single_position_zero_withdrawable(self) -> None:
        position = make_position(available_shares=500)

        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            positions_to_redeem = await select_positions(
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                vault_to_harvest_params={VAULT_1: None},
                vault_to_withdrawable_assets={VAULT_1: Wei(0)},
            )
        assert positions_to_redeem == []

    async def test_queued_shares_limits_redemption(self) -> None:
        position = make_position(available_shares=500)

        positions_to_redeem = await select_positions(
            os_token_positions=[position],
            queued_shares=200,
            converter=make_converter(),
            vault_to_harvest_params={VAULT_1: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
        )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].shares_to_redeem == Wei(200)

    async def test_multiple_positions_limited_by_withdrawable_assets(self) -> None:
        pos1 = make_position(owner=OWNER_1, available_shares=500)
        pos2 = make_position(owner=OWNER_2, available_shares=1000)

        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            positions_to_redeem = await select_positions(
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                vault_to_harvest_params={VAULT_1: None},
                vault_to_withdrawable_assets={VAULT_1: Wei(700)},
            )
        assert len(positions_to_redeem) == 2
        assert positions_to_redeem[0].owner == OWNER_1
        assert positions_to_redeem[0].shares_to_redeem == Wei(500)
        assert positions_to_redeem[1].owner == OWNER_2
        assert positions_to_redeem[1].shares_to_redeem == Wei(200)

    async def test_multiple_vaults_both_selected(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, available_shares=800)

        positions_to_redeem = await select_positions(
            os_token_positions=[pos1, pos2],
            queued_shares=10000,
            converter=make_converter(100, 100),
            vault_to_harvest_params={VAULT_1: None, VAULT_2: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000), VAULT_2: Wei(10000)},
        )
        assert len(positions_to_redeem) == 2

    async def test_stops_across_vaults_when_queued_shares_exhausted(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, available_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, available_shares=800)

        positions_to_redeem = await select_positions(
            os_token_positions=[pos1, pos2],
            queued_shares=500,
            converter=make_converter(100, 100),
            vault_to_harvest_params={VAULT_1: None, VAULT_2: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000), VAULT_2: Wei(10000)},
        )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].vault == VAULT_1

    async def test_preserves_original_amount(self) -> None:
        pos = make_position(amount=1000, available_shares=500)

        positions_to_redeem = await select_positions(
            os_token_positions=[pos],
            queued_shares=200,
            converter=make_converter(),
            vault_to_harvest_params={VAULT_1: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
        )
        assert positions_to_redeem[0].amount == Wei(1000)
        assert positions_to_redeem[0].shares_to_redeem == Wei(200)

    async def test_stops_within_vault_when_queued_shares_exhausted(self) -> None:
        pos1 = make_position(owner=OWNER_1, available_shares=400)
        pos2 = make_position(owner=OWNER_2, available_shares=300)

        positions_to_redeem = await select_positions(
            os_token_positions=[pos1, pos2],
            queued_shares=400,
            converter=make_converter(100, 100),
            vault_to_harvest_params={VAULT_1: None},
            vault_to_withdrawable_assets={VAULT_1: Wei(10000)},
        )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].owner == OWNER_1

    async def test_partial_fills_first_then_exhausts_withdrawable(self) -> None:
        pos1 = make_position(owner=OWNER_1, available_shares=1000)
        pos2 = make_position(owner=OWNER_2, available_shares=100)

        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            positions_to_redeem = await select_positions(
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                vault_to_harvest_params={VAULT_1: None},
                vault_to_withdrawable_assets={VAULT_1: Wei(500)},
            )
        assert len(positions_to_redeem) == 1
        assert positions_to_redeem[0].owner == OWNER_1
        assert positions_to_redeem[0].shares_to_redeem == Wei(500)


class TestFetchVaultWithdrawableAssets:
    async def test_calls_withdrawable_per_vault(self) -> None:
        mock_withdrawable = AsyncMock(return_value=Wei(10000))

        with patch(f'{MODULE}.get_withdrawable_assets', mock_withdrawable):
            result = await fetch_vault_withdrawable_assets(
                vaults={VAULT_1, VAULT_2},
                vault_to_harvest_params={VAULT_1: None, VAULT_2: None},
            )

        assert mock_withdrawable.call_count == 2
        assert result[VAULT_1] == Wei(10000)
        assert result[VAULT_2] == Wei(10000)

    async def test_passes_harvest_params(self) -> None:
        hp = make_harvest_params()
        mock_withdrawable = AsyncMock(return_value=Wei(10000))

        with patch(f'{MODULE}.get_withdrawable_assets', mock_withdrawable):
            await fetch_vault_withdrawable_assets(
                vaults={VAULT_1},
                vault_to_harvest_params={VAULT_1: hp},
            )

        mock_withdrawable.assert_called_once_with(VAULT_1, hp)


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
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, amount=1000)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, amount=2000)

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
        pos = make_position(amount=1000)
        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(1000)]),
        ):
            result = await calculate_redeemable_shares(
                [pos], tree_nonce=5, block_number=BlockNumber(100)
            )
        assert result == []

    async def test_partial_processed_shares(self) -> None:
        pos = make_position(amount=1000)
        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(300)]),
        ):
            result = await calculate_redeemable_shares(
                [pos], tree_nonce=5, block_number=BlockNumber(100)
            )
        assert len(result) == 1
        assert result[0].available_shares == Wei(700)
        assert result[0].amount == Wei(1000)

    async def test_multiple_positions_mixed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, amount=1000)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, amount=2000)

        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(1000), Wei(500)]),
        ):
            result = await calculate_redeemable_shares(
                [pos1, pos2], tree_nonce=5, block_number=BlockNumber(100)
            )
        assert len(result) == 1
        assert result[0].owner == OWNER_2
        assert result[0].available_shares == Wei(1500)


class TestTryRedeemMetaVault:
    async def test_not_meta_vault(self) -> None:
        with patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)):
            result = await _try_redeem_meta_vault(
                vault_address=VAULT_1,
                deficit=Wei(400),
                current_withdrawable=Wei(100),
                harvest_params=None,
            )
        assert result == Wei(100)

    async def test_meta_vault_successful_redeem(self) -> None:
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(
                f'{MODULE}.get_withdrawable_assets',
                new=AsyncMock(return_value=Wei(600)),
            ),
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(return_value='0xabc')
            result = await _try_redeem_meta_vault(
                vault_address=VAULT_1,
                deficit=Wei(400),
                current_withdrawable=Wei(100),
                harvest_params=None,
            )
        assert result == Wei(600)
        mock_redeemer.redeem_sub_vaults_assets.assert_called_once_with(VAULT_1, Wei(400))

    async def test_meta_vault_failed_redeem(self) -> None:
        with (
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(side_effect=RuntimeError('fail'))
            result = await _try_redeem_meta_vault(
                vault_address=VAULT_1,
                deficit=Wei(400),
                current_withdrawable=Wei(100),
                harvest_params=None,
            )
        assert result == Wei(100)


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
        pos = make_position(vault=VAULT_1, amount=1000, available_shares=500, shares_to_redeem=500)
        harvest_params = make_harvest_params()

        with _mock_execute_redemption(tx_status=1) as mocks:
            mock_vault = mocks['MockVaultContract'].return_value
            mock_vault.contract_address = VAULT_1
            mock_vault.get_update_state_call.return_value = HexStr('0xupdate')

            result = await execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: harvest_params},
                tree_nonce=5,
            )

        assert result is not None
        mock_vault.get_update_state_call.assert_called_once_with(harvest_params)

    async def test_successful_without_harvest_params(self) -> None:
        pos = make_position(vault=VAULT_1, amount=1000, available_shares=500, shares_to_redeem=500)

        with _mock_execute_redemption(tx_status=1):
            result = await execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                tree_nonce=5,
            )

        assert result is not None

    async def test_web3_exception(self) -> None:
        pos = make_position(amount=1000, available_shares=500, shares_to_redeem=500)

        with _mock_execute_redemption(tx_side_effect=Web3Exception('fail')):
            result = await execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                tree_nonce=5,
            )

        assert result is None

    async def test_tx_receipt_fails(self) -> None:
        pos = make_position(amount=1000, available_shares=500, shares_to_redeem=500)

        with _mock_execute_redemption(tx_status=0):
            result = await execute_redemption(
                all_positions=[pos],
                positions_to_redeem=[pos],
                vault_to_harvest_params={VAULT_1: None},
                tree_nonce=5,
            )

        assert result is None


class TestProcess:
    async def test_no_queued_shares(self) -> None:
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(0))
            await process(block_number=BlockNumber(100))

    async def test_no_eligible_positions(self) -> None:
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100))
            mocks['mock_execute'].assert_not_called()

    async def test_successful_redemption(self) -> None:
        positions = [make_position(amount=1000, available_shares=500, shares_to_redeem=500)]

        with _mock_process(positions=positions) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100))
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
        patch(f'{MODULE}.VaultContract') as MockVaultContract,
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(f'{MODULE}.multicall_contract'),
        patch(f'{MODULE}.transaction_gas_wrapper', new=tx_mock),
        patch(f'{MODULE}.execution_client', new=mock_client),
        patch(f'{MODULE}.settings') as mock_settings,
    ):
        mock_settings.execution_transaction_timeout = 120
        mock_redeemer.encode_abi.return_value = HexStr('0xredeem')
        mock_redeemer.contract_address = VAULT_2
        yield {
            'MockVaultContract': MockVaultContract,
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
            f'{MODULE}.fetch_vault_withdrawable_assets',
            new=AsyncMock(return_value={VAULT_1: Wei(10000)}),
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
