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
    _build_multi_proof,
    _process_exit_queue,
    _startup_check,
    _submit_redeem_position,
    calculate_redeemable_shares,
    fetch_positions_from_ipfs,
    process,
    redeem_positions,
    update_vaults_state,
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
                tree_nonce=5,
            )
        mocks['submit_mock'].assert_not_called()

    async def test_single_position_sufficient_assets(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(1000)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(),
                tree_nonce=5,
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(500)

    async def test_single_position_insufficient_assets_partial_fill(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(100)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(100)

    async def test_single_position_zero_withdrawable_skipped(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(0)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        mocks['submit_mock'].assert_not_called()

    async def test_queued_shares_limits_redemption(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=200,
                converter=make_converter(),
                tree_nonce=5,
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(200)

    async def test_multiple_positions_share_vault_cache(self) -> None:
        """Withdrawable is fetched once per vault, decremented after each redemption."""
        pos1 = make_position(owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(owner=OWNER_2, unprocessed_shares=1000)

        get_withdrawable = AsyncMock(return_value=Wei(700))
        with _mock_redeem_positions(withdrawable=get_withdrawable) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        # Two redemption transactions (one per position)
        assert mocks['submit_mock'].await_count == 2
        # Single fetch — second position uses cached value
        assert get_withdrawable.await_count == 1

        first_position = _submitted_position(mocks, 0)
        second_position = _submitted_position(mocks, 1)
        assert first_position.owner == OWNER_1 and first_position.shares_to_redeem == Wei(500)
        assert second_position.owner == OWNER_2 and second_position.shares_to_redeem == Wei(200)

    async def test_stops_across_vaults_when_queued_shares_exhausted(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=800)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=500,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        # Only the first position's vault is redeemed
        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).vault == VAULT_1

    async def test_preserves_original_leaf_shares_in_call(self) -> None:
        pos = make_position(leaf_shares=1000, unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=200,
                converter=make_converter(),
                tree_nonce=5,
            )

        submitted = _submitted_position(mocks)
        # leafShares preserved, sharesToRedeem capped by queued_shares
        assert submitted.leaf_shares == Wei(1000)
        assert submitted.shares_to_redeem == Wei(200)

    async def test_meta_vault_position_skipped(self) -> None:
        """Positions on meta vaults are skipped entirely — no submit, no fetch."""
        pos = make_position(unprocessed_shares=500)
        get_withdrawable = AsyncMock(return_value=Wei(10000))

        with _mock_redeem_positions(withdrawable=get_withdrawable, is_meta_vault=True) as mocks:
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        mocks['submit_mock'].assert_not_called()
        get_withdrawable.assert_not_called()

    async def test_submit_failure_aborts_iteration(self) -> None:
        """A failed submission aborts the loop; subsequent positions are not attempted."""
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=500)

        with _mock_redeem_positions(
            withdrawable=Wei(10000),
            submit_results=[None, BlockNumber(123)],
        ) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        # Only the first position is attempted; loop aborted
        assert mocks['submit_mock'].await_count == 1


# --- Async function tests (with mocks) ---


class TestSubmitRedeemPosition:
    async def test_success_returns_receipt_block(self) -> None:
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_submit_redeem_position(tx_status=1) as mocks:
            result = await _submit_redeem_position(
                position=position,
                all_positions=[position],
                tree_nonce=5,
            )
        assert result == BlockNumber(456)
        mocks['transaction_gas_wrapper'].assert_awaited_once()
        mocks['client'].eth.wait_for_transaction_receipt.assert_awaited_once()

    async def test_tx_status_zero_returns_none(self) -> None:
        """A reverted on-chain tx returns None without raising."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_submit_redeem_position(tx_status=0):
            result = await _submit_redeem_position(
                position=position,
                all_positions=[position],
                tree_nonce=5,
            )
        assert result is None

    @pytest.mark.parametrize('exc_class', [Web3Exception, RuntimeError, ValueError])
    async def test_tx_build_failure_returns_none(self, exc_class: type[Exception]) -> None:
        """Each caught exception during tx build/send returns None."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_submit_redeem_position(send_exception=exc_class('boom')) as mocks:
            result = await _submit_redeem_position(
                position=position,
                all_positions=[position],
                tree_nonce=5,
            )
        assert result is None
        # Receipt is never awaited when the build step raised
        mocks['client'].eth.wait_for_transaction_receipt.assert_not_awaited()

    async def test_unexpected_exception_propagates(self) -> None:
        """Exceptions outside the (Web3Exception, RuntimeError, ValueError) catch list propagate."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_submit_redeem_position(send_exception=KeyError('boom')):
            with pytest.raises(KeyError):
                await _submit_redeem_position(
                    position=position,
                    all_positions=[position],
                    tree_nonce=5,
                )


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
        with _mock_update_vaults_state() as mocks:
            await update_vaults_state(vaults=[], block_number=BlockNumber(100))
        mocks['harvest_params'].assert_not_called()
        mocks['redeemer'].batch_update_vault_state.assert_not_called()

    async def test_meta_vault_excluded_from_multicall(self) -> None:
        """A meta vault in the input list is filtered out — not harvested by this command."""
        with _mock_update_vaults_state(
            is_meta_vault_addresses={VAULT_1},
            harvest_params={VAULT_2: make_harvest_params()},
        ) as mocks:
            await update_vaults_state(vaults=[VAULT_1, VAULT_2], block_number=BlockNumber(100))

        mocks['harvest_params'].assert_awaited_once_with([VAULT_2], BlockNumber(100))
        mocks['redeemer'].batch_update_vault_state.assert_awaited_once_with(
            {VAULT_2: make_harvest_params()}
        )

    @pytest.mark.parametrize(
        'has_params, expected_multicall_calls',
        [(True, 1), (False, 0)],
        ids=['with_params', 'no_params'],
    )
    async def test_regular_vault_multicall_gated_by_harvest_params(
        self, has_params: bool, expected_multicall_calls: int
    ) -> None:
        """A None entry in get_multiple_harvest_params skips that vault from the multicall."""
        params: HarvestParams | None = make_harvest_params() if has_params else None
        with _mock_update_vaults_state(harvest_params={VAULT_1: params}) as mocks:
            await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))

        assert mocks['redeemer'].batch_update_vault_state.await_count == expected_multicall_calls
        if has_params:
            mocks['redeemer'].batch_update_vault_state.assert_awaited_once_with({VAULT_1: params})

    async def test_multicall_tx_failure_raises(self) -> None:
        """A failed multicall receipt aborts the round."""
        with _mock_update_vaults_state(
            harvest_params={VAULT_1: make_harvest_params()},
            multicall_tx_status=0,
        ):
            with pytest.raises(
                RuntimeError, match='OsTokenRedeemer updateVaultState multicall tx failed'
            ):
                await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))


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
        mocks['mock_update_state'].assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_zero_nonce_skipped(self) -> None:
        """nonce == 0 skips the round before any state mutation. Guards prev_nonce = nonce - 1."""
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=0)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_update_state'].assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_no_positions_from_ipfs(self) -> None:
        """Empty IPFS positions: skip update_vaults_state and redeem_positions."""
        with _mock_process(positions=[]) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_update_state'].assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_no_eligible_positions(self) -> None:
        """IPFS returns positions but calculate_redeemable_shares filters them all out."""
        pos = make_position(leaf_shares=1000)
        with (
            _mock_process(positions=[pos]) as mocks,
            patch(f'{MODULE}.calculate_redeemable_shares', new=AsyncMock(return_value=[])),
        ):
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_update_state'].assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_successful_redemption(self) -> None:
        positions = [make_position(leaf_shares=1000, unprocessed_shares=500, shares_to_redeem=500)]

        with _mock_process(positions=positions) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)

            # Verify update_vaults_state runs before redeem_positions
            manager = MagicMock()
            manager.attach_mock(mocks['mock_update_state'], 'update_state')
            manager.attach_mock(mocks['mock_redeem'], 'redeem')

            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))

        assert [c[0] for c in manager.mock_calls] == ['update_state', 'redeem']

        update_call = mocks['mock_update_state'].await_args
        # Unique vault list derived from os_token_positions
        assert update_call.kwargs['vaults'] == [VAULT_1]

        redeem_call = mocks['mock_redeem'].await_args
        # tree_nonce must use prev_nonce = nonce - 1 (off-by-one is critical)
        assert redeem_call.kwargs['tree_nonce'] == 4
        # queued_shares is forwarded as raw shares, not converted to assets
        assert redeem_call.kwargs['queued_shares'] == 1000


# --- Helpers ---


@contextmanager
def _mock_redeem_positions(
    withdrawable: Wei | AsyncMock | None = None,
    is_meta_vault: bool = False,
    submit_results: list[BlockNumber | None] | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for redeem_positions tests.

    ``withdrawable`` may be a constant Wei value (returned on every call) or an
    AsyncMock for fine-grained control (e.g. ``side_effect=[...]`` for sequenced returns).
    ``submit_results`` controls per-call return values of _submit_redeem_position;
    a ``None`` entry models a failed submission that should abort the round.
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
        submit_mock = AsyncMock(return_value=BlockNumber(123))

    with (
        patch(f'{MODULE}.get_withdrawable_assets', new=get_withdrawable),
        patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=is_meta_vault)),
        patch(f'{MODULE}._submit_redeem_position', new=submit_mock),
        patch(
            f'{MODULE}.wait_for_execution_endpoints_synced',
            new=AsyncMock(),
        ) as wait_synced_mock,
    ):
        yield {
            'submit_mock': submit_mock,
            'wait_synced_mock': wait_synced_mock,
        }


def _submitted_position(mocks: dict[str, MagicMock], index: int = 0) -> OsTokenPosition:
    """Return the position passed to the Nth _submit_redeem_position call."""
    return mocks['submit_mock'].call_args_list[index].kwargs['position']


@contextmanager
def _mock_submit_redeem_position(
    tx_status: int = 1,
    send_exception: BaseException | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for _submit_redeem_position tests.

    ``send_exception`` makes ``transaction_gas_wrapper`` raise; otherwise it returns
    a fake tx that resolves to a receipt with the given ``tx_status``.
    """
    tx = HexBytes(b'\xab' * 32)
    mock_client = AsyncMock()
    mock_client.eth.wait_for_transaction_receipt = AsyncMock(
        return_value={'status': tx_status, 'blockNumber': BlockNumber(456)},
    )

    if send_exception is not None:
        gas_wrapper = AsyncMock(side_effect=send_exception)
    else:
        gas_wrapper = AsyncMock(return_value=tx)

    with (
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(f'{MODULE}.transaction_gas_wrapper', new=gas_wrapper),
        patch(f'{MODULE}.execution_client', new=mock_client),
        patch(f'{MODULE}.settings') as mock_settings,
    ):
        mock_settings.execution_transaction_timeout = 120
        mock_redeemer.contract.functions.redeemOsTokenPositions = MagicMock()
        yield {
            'redeemer': mock_redeemer,
            'transaction_gas_wrapper': gas_wrapper,
            'client': mock_client,
        }


@contextmanager
def _mock_update_vaults_state(
    harvest_params: dict[ChecksumAddress, HarvestParams | None] | None = None,
    is_meta_vault_addresses: set[ChecksumAddress] | None = None,
    multicall_tx_status: int = 1,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for update_vaults_state tests.

    ``is_meta_vault_addresses`` lists addresses that should be treated as meta vaults
    (and therefore filtered out). ``harvest_params`` is the dict returned by
    get_multiple_harvest_params; a None value for a vault skips it from the
    multicall (production behavior). ``multicall_tx_status`` controls the receipt
    status of the OsTokenRedeemer.batch_update_vault_state batched tx.
    """
    harvest_params = {} if harvest_params is None else harvest_params
    meta_addresses = is_meta_vault_addresses or set()

    mock_client = AsyncMock()
    mock_client.eth.wait_for_transaction_receipt = AsyncMock(
        return_value={'status': multicall_tx_status}
    )

    async def is_meta_vault_side_effect(addr: ChecksumAddress) -> bool:
        return addr in meta_addresses

    with (
        patch(f'{MODULE}.is_meta_vault', side_effect=is_meta_vault_side_effect),
        patch(
            f'{MODULE}.get_multiple_harvest_params',
            new=AsyncMock(return_value=harvest_params),
        ) as mock_harvest_params,
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(f'{MODULE}.execution_client', new=mock_client),
        patch(f'{MODULE}.settings') as mock_settings,
    ):
        mock_settings.execution_transaction_timeout = 120
        mock_redeemer.batch_update_vault_state = AsyncMock(return_value='0x' + '11' * 32)
        yield {
            'harvest_params': mock_harvest_params,
            'redeemer': mock_redeemer,
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
    unprocessed_shares: int = 500,
    shares_to_redeem: int = 0,
) -> OsTokenPosition:
    """Build a test position. ``unprocessed_shares`` defaults to a non-zero value so
    redemption-loop tests don't silently no-op when a caller forgets to set it."""
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
