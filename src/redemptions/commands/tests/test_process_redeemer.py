import asyncio
from contextlib import contextmanager
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber, ChecksumAddress
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Gwei, Wei

from src.redemptions.commands.process_redeemer import (
    _startup_check,
    process,
    redeem_positions,
)
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.os_token_converter import OsTokenConverter
from src.redemptions.typings import OsTokenPosition

MODULE = 'src.redemptions.commands.process_redeemer'

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
VAULT_2 = Web3.to_checksum_address('0x' + '22' * 20)
OWNER_1 = Web3.to_checksum_address('0x' + '33' * 20)
OWNER_2 = Web3.to_checksum_address('0x' + '44' * 20)


class TestRedeemPositions:
    async def test_empty_positions(self) -> None:
        with _mock_redeem_positions() as mocks:
            await redeem_positions(
                tree=make_tree(),
                os_token_positions=[],
                converter=make_converter(),
                block_number=BlockNumber(100),
            )
        mocks['submit_mock'].assert_not_called()

    async def test_single_position_sufficient_assets(self) -> None:
        position = make_position(processed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(1000)) as mocks:
            await redeem_positions(
                tree=make_tree([position]),
                os_token_positions=[position],
                converter=make_converter(),
                block_number=BlockNumber(100),
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(500)

    async def test_single_position_insufficient_assets_partial_fill(self) -> None:
        position = make_position(processed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(100)) as mocks:
            await redeem_positions(
                tree=make_tree([position]),
                os_token_positions=[position],
                converter=make_converter(100, 100),
                block_number=BlockNumber(100),
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(100)

    async def test_single_position_zero_withdrawable_skipped(self) -> None:
        position = make_position(processed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(0)) as mocks:
            await redeem_positions(
                tree=make_tree([position]),
                os_token_positions=[position],
                converter=make_converter(100, 100),
                block_number=BlockNumber(100),
            )

        mocks['submit_mock'].assert_not_called()

    async def test_multiple_positions_share_vault_cache(self) -> None:
        """Withdrawable is fetched once per vault, decremented after each redemption."""
        pos1 = make_position(owner=OWNER_1, processed_shares=500)
        pos2 = make_position(owner=OWNER_2, processed_shares=0)

        get_withdrawable = AsyncMock(return_value=Wei(700))
        with _mock_redeem_positions(withdrawable=get_withdrawable) as mocks:
            await redeem_positions(
                tree=make_tree([pos1, pos2]),
                os_token_positions=[pos1, pos2],
                converter=make_converter(100, 100),
                block_number=BlockNumber(100),
            )

        # Two redemption transactions (one per position)
        assert mocks['submit_mock'].await_count == 2
        # Single fetch — second position uses cached value
        assert get_withdrawable.await_count == 1

        first_position = _submitted_position(mocks, 0)
        second_position = _submitted_position(mocks, 1)
        assert first_position.owner == OWNER_1 and first_position.shares_to_redeem == Wei(500)
        assert second_position.owner == OWNER_2 and second_position.shares_to_redeem == Wei(200)

    async def test_pre_capped_shares_to_redeem_submitted_not_unprocessed(self) -> None:
        """assign_shares_to_redeem may cap shares_to_redeem below unprocessed_shares.
        redeem_positions must submit the pre-capped value, not re-derive from unprocessed_shares."""
        # unprocessed_shares = 1000, but budget was exhausted mid-position
        pos = make_position(leaf_shares=1000, processed_shares=0, shares_to_redeem=400)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                tree=make_tree([pos]),
                os_token_positions=[pos],
                converter=make_converter(),
                block_number=BlockNumber(100),
            )

        submitted = _submitted_position(mocks)
        assert submitted.shares_to_redeem == Wei(400)

    async def test_preserves_original_leaf_shares_in_call(self) -> None:
        pos = make_position(leaf_shares=1000, processed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                tree=make_tree([pos]),
                os_token_positions=[pos],
                converter=make_converter(),
                block_number=BlockNumber(100),
            )

        submitted = _submitted_position(mocks)
        assert submitted.leaf_shares == Wei(1000)
        assert submitted.shares_to_redeem == Wei(500)

    async def test_meta_vault_position_skipped(self) -> None:
        """A meta-vault position is unexpected and must be skipped without redeeming."""
        pos = make_position(processed_shares=500)
        get_withdrawable = AsyncMock(return_value=Wei(10000))

        with _mock_redeem_positions(withdrawable=get_withdrawable, is_meta_vault=True) as mocks:
            await redeem_positions(
                tree=make_tree([pos]),
                os_token_positions=[pos],
                converter=make_converter(100, 100),
                block_number=BlockNumber(100),
            )

        mocks['submit_mock'].assert_not_called()
        get_withdrawable.assert_not_called()

    async def test_unharvested_vault_skipped(self) -> None:
        """A vault that requires a state update is skipped without redeeming."""
        pos = make_position(processed_shares=500)

        with _mock_redeem_positions(
            withdrawable=Wei(10000),
            state_update_required=True,
        ) as mocks:
            await redeem_positions(
                tree=make_tree([pos]),
                os_token_positions=[pos],
                converter=make_converter(100, 100),
                block_number=BlockNumber(100),
            )

        mocks['get_withdrawable'].assert_not_called()
        mocks['submit_mock'].assert_not_called()

    async def test_submit_failure_skips_position(self) -> None:
        """A failed submission skips that position; subsequent positions are still attempted."""
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, processed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, processed_shares=500)

        with _mock_redeem_positions(
            withdrawable=Wei(10000),
            submit_results=[False, True],
        ) as mocks:
            await redeem_positions(
                tree=make_tree([pos1, pos2]),
                os_token_positions=[pos1, pos2],
                converter=make_converter(100, 100),
                block_number=BlockNumber(100),
            )

        # The first position fails but the round continues to the second
        assert mocks['submit_mock'].await_count == 2


# --- Async function tests (with mocks) ---


class TestStartupCheck:
    async def test_authorized(self) -> None:
        wallet_address = faker.eth_address()
        mock_wallet = MagicMock()
        mock_wallet.account.address = wallet_address
        with (
            _mock_startup_checks(),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.wallet', new=mock_wallet),
        ):
            mock_redeemer.positions_manager = AsyncMock(return_value=wallet_address)
            await _startup_check()

    async def test_unauthorized(self) -> None:
        mock_wallet = MagicMock()
        mock_wallet.account.address = faker.eth_address()
        with (
            _mock_startup_checks(),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.wallet', new=mock_wallet),
        ):
            mock_redeemer.positions_manager = AsyncMock(return_value=faker.eth_address())
            with pytest.raises(RuntimeError, match='Position Manager role must be assigned'):
                await _startup_check()


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

    async def test_gas_price_check_fails(self) -> None:
        """check_gas_price → False short-circuits before exit_queue or redemption work."""
        with (
            _mock_process() as mocks,
            patch(f'{MODULE}.check_gas_price', new=AsyncMock(return_value=False)),
        ):
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_redeemer'].queued_shares.assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_zero_nonce_skipped(self) -> None:
        """nonce == 0 skips the round before any state mutation. Guards prev_nonce = nonce - 1."""
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=0)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_redeem'].assert_not_called()

    async def test_no_positions_from_ipfs(self) -> None:
        """Empty IPFS positions: skip redeem_positions."""
        with _mock_process(positions=[]) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_redeem'].assert_not_called()

    async def test_no_eligible_positions(self) -> None:
        """IPFS returns positions but assign_shares_to_redeem filters them all out."""
        pos = make_position(leaf_shares=1000)
        with (
            _mock_process(positions=[pos]) as mocks,
            patch(f'{MODULE}.assign_shares_to_redeem', new=AsyncMock(return_value=[])),
        ):
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_redeem'].assert_not_called()

    async def test_successful_redemption(self) -> None:
        positions = [make_position(leaf_shares=1000, processed_shares=500, shares_to_redeem=500)]

        with _mock_process(positions=positions) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)

            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))

        mocks['mock_redeem'].assert_awaited_once()
        redeem_call = mocks['mock_redeem'].await_args
        # The merkle tree is built from the fetched nonce; leaves use nonce - 1 internally
        assert redeem_call.kwargs['tree'].nonce == 5


# --- Helpers ---


@contextmanager
def _mock_startup_checks() -> Iterator[None]:
    """Patch the execution-node, network and wallet-balance checks run by _startup_check,
    leaving the Position Manager role check under test."""
    with (
        patch(f'{MODULE}.wait_for_execution_node', new=AsyncMock()),
        patch(f'{MODULE}.check_execution_nodes_network', new=AsyncMock()),
        patch(f'{MODULE}.check_wallet_balance', new=AsyncMock()),
    ):
        yield


@contextmanager
def _mock_redeem_positions(
    withdrawable: Wei | AsyncMock | None = None,
    is_meta_vault: bool = False,
    state_update_required: bool = False,
    submit_results: list[bool] | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for redeem_positions tests.

    ``withdrawable`` may be a constant Wei value (returned on every call) or an
    AsyncMock for fine-grained control (e.g. ``side_effect=[...]`` for sequenced returns).
    ``state_update_required`` drives VaultContract.is_state_update_required, which gates
    the unharvested-vault skip. ``submit_results`` controls per-call return values of
    tx_redeem_position; a ``False`` entry models a failed submission that should
    abort the round. Simulation always succeeds; each live position is simulated first.
    """
    if isinstance(withdrawable, AsyncMock):
        get_withdrawable = withdrawable
    else:
        get_withdrawable = AsyncMock(
            return_value=withdrawable if withdrawable is not None else Wei(0)
        )

    if submit_results is not None:
        submit_mock = AsyncMock(side_effect=submit_results)
    else:
        submit_mock = AsyncMock(return_value=True)

    simulate_mock = AsyncMock(return_value=True)

    vault_contract = MagicMock()
    vault_contract.is_state_update_required = AsyncMock(return_value=state_update_required)

    with (
        patch(f'{MODULE}.get_withdrawable_assets', new=get_withdrawable),
        patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=is_meta_vault)),
        patch(f'{MODULE}.VaultContract', return_value=vault_contract),
        patch(f'{MODULE}.simulate_redeem_position', new=simulate_mock),
        patch(f'{MODULE}.tx_redeem_position', new=submit_mock),
    ):
        yield {
            'submit_mock': submit_mock,
            'simulate_mock': simulate_mock,
            'get_withdrawable': get_withdrawable,
        }


def _submitted_position(mocks: dict[str, MagicMock], index: int = 0) -> OsTokenPosition:
    """Return the position passed to the Nth tx_redeem_position call."""
    return mocks['submit_mock'].call_args_list[index].kwargs['position']


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
        patch(f'{MODULE}.tx_process_exit_queue', new=AsyncMock()),
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(
            f'{MODULE}.create_os_token_converter',
            new=AsyncMock(return_value=make_converter()),
        ),
        patch(f'{MODULE}.settings') as mock_settings,
        patch(f'{MODULE}.get_finalized_block_number', new=AsyncMock(return_value=BlockNumber(100))),
        patch(f'{MODULE}.update_positions_cache', new=AsyncMock()),
        patch(
            f'{MODULE}.cached_fetch_positions_from_ipfs',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.fetch_positions_with_processed_shares',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.assign_shares_to_redeem',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.update_processed_shares_cache',
            new=AsyncMock(),
        ),
        patch(
            f'{MODULE}.redeem_positions',
            new=AsyncMock(),
        ) as mock_redeem,
        patch(f'{MODULE}.execution_client', new=mock_client),
    ):
        mock_settings.network_config.VAULT_BALANCE_SYMBOL = 'ETH'
        mock_redeemer.can_process_exit_queue = AsyncMock(return_value=False)
        yield {
            'mock_redeemer': mock_redeemer,
            'mock_redeem': mock_redeem,
        }


def make_converter(total_assets: int = 110, total_shares: int = 100) -> OsTokenConverter:
    return OsTokenConverter(Wei(total_assets), Wei(total_shares))


def make_tree(
    positions: list[OsTokenPosition] | None = None, nonce: int = 5
) -> PositionsMerkleTree:
    """Build a positions merkle tree. Defaults to a single position so callers that
    only need a valid tree (e.g. when tx_redeem_position is mocked) can omit it."""
    return PositionsMerkleTree(positions or [make_position()], nonce)


def make_position(
    vault: ChecksumAddress = VAULT_1,
    owner: ChecksumAddress = OWNER_1,
    leaf_shares: int = 1000,
    processed_shares: int = 500,
    shares_to_redeem: int | None = None,
) -> OsTokenPosition:
    """Build a test position.

    ``processed_shares`` defaults to half of ``leaf_shares`` so redemption-loop
    tests don't silently no-op when a caller forgets to set it.

    ``shares_to_redeem`` defaults to ``leaf_shares - processed_shares``
    (i.e. unprocessed shares), mirroring what ``assign_shares_to_redeem`` would set
    before handing positions to ``redeem_positions``.  Pass an explicit value
    when testing the partial-fill or zero-withdrawable edge cases.
    """
    effective_shares_to_redeem = (
        shares_to_redeem if shares_to_redeem is not None else leaf_shares - processed_shares
    )
    return OsTokenPosition(
        vault=vault,
        owner=owner,
        leaf_shares=Wei(leaf_shares),
        processed_shares=Wei(processed_shares),
        shares_to_redeem=Wei(effective_shares_to_redeem),
    )
