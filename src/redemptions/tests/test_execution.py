from contextlib import contextmanager
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import ContractCustomError

from src.redemptions.execution import (
    simulate_redeem_position,
    tx_process_exit_queue,
    tx_redeem_position,
    update_vaults_state,
)
from src.redemptions.tests.factories import make_position, make_tree

MODULE = 'src.redemptions.execution'

# error_verbose reads settings.verbose on the failure paths exercised below.
pytestmark = pytest.mark.usefixtures('fake_settings')

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
VAULT_2 = Web3.to_checksum_address('0x' + '22' * 20)
OWNER_1 = Web3.to_checksum_address('0x' + '33' * 20)


class TestTxRedeemPosition:
    async def test_success_returns_true(self) -> None:
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_tx_redeem_position(tx_status=1) as mocks:
            result = await tx_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is True
        mocks['tx_manager'].transact.assert_awaited_once()
        mocks['wait_for_execution_endpoints_synced'].assert_awaited_once_with(BlockNumber(456))

    async def test_tx_status_zero_returns_false(self) -> None:
        """A reverted on-chain tx returns False without raising."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_tx_redeem_position(tx_status=0) as mocks:
            result = await tx_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is False
        # No sync barrier when the tx reverted
        mocks['wait_for_execution_endpoints_synced'].assert_not_awaited()

    async def test_tx_build_failure_returns_false(self) -> None:
        """An error during tx build/send returns False, so a single bad position
        cannot abort the whole redemption run."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_tx_redeem_position(send_exception=Exception('boom')) as mocks:
            result = await tx_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is False
        # No sync barrier when the tx build/send step raised
        mocks['wait_for_execution_endpoints_synced'].assert_not_awaited()

    async def test_custom_error_returns_false(self) -> None:
        """A custom error revert is decoded and returns False without raising."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        error = ContractCustomError('reverted', data='0x1234abcd')
        with _mock_tx_redeem_position(send_exception=error) as mocks:
            result = await tx_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is False
        mocks['redeemer'].decode_custom_error.assert_called_once_with('0x1234abcd')
        mocks['wait_for_execution_endpoints_synced'].assert_not_awaited()


class TestSimulateRedeemPosition:
    async def test_success_returns_true(self) -> None:
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_simulate_redeem_position() as mocks:
            result = await simulate_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is True
        mocks['call'].assert_awaited_once()

    async def test_call_failure_returns_false(self) -> None:
        """A failed simulation returns False without raising."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_simulate_redeem_position(call_exception=Exception('boom')):
            result = await simulate_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is False

    async def test_custom_error_returns_false(self) -> None:
        """A custom error revert during simulation is decoded and returns False."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        error = ContractCustomError('reverted', data='0x1234abcd')
        with _mock_simulate_redeem_position(call_exception=error) as mocks:
            result = await simulate_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is False
        mocks['redeemer'].decode_custom_error.assert_called_once_with('0x1234abcd')


class TestTxProcessExitQueue:
    @pytest.mark.parametrize('tx_status', [1, 0])
    async def test_process_exit_queue(self, tx_status: int) -> None:
        """Calls processExitQueue() and submits it via tx_manager, regardless of
        whether the tx confirms (``tx_status=1``) or fails (``tx_status=0``,
        represented as ``tx_manager.transact`` returning ``None``)."""
        tx_receipt = {'status': 1, 'transactionHash': HexBytes(b'\xab' * 32)} if tx_status else None
        mock_tx_manager = MagicMock()
        mock_tx_manager.transact = AsyncMock(return_value=tx_receipt)
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.tx_manager', new=mock_tx_manager),
        ):
            await tx_process_exit_queue()
            mock_redeemer.contract.functions.processExitQueue.assert_called_once()
            mock_tx_manager.transact.assert_awaited_once()

    async def test_custom_error_is_decoded(self) -> None:
        """A custom error revert is decoded and swallowed."""
        mock_tx_manager = MagicMock()
        mock_tx_manager.transact = AsyncMock(
            side_effect=ContractCustomError('reverted', data='0x1234abcd')
        )
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.tx_manager', new=mock_tx_manager),
        ):
            await tx_process_exit_queue()
            mock_redeemer.decode_custom_error.assert_called_once_with('0x1234abcd')


class TestUpdateVaultsState:
    async def test_submits_multicall_for_harvestable_vaults(self) -> None:
        with _mock_update_vaults_state() as mocks:
            result = await update_vaults_state(vaults=[VAULT_1, VAULT_2])
        assert result is True
        mocks['tx_aggregate'].assert_awaited_once()
        await_args = mocks['tx_aggregate'].await_args
        assert await_args is not None
        # One updateState call per harvestable vault.
        assert len(await_args.args[0]) == 2

    async def test_skips_meta_vaults(self) -> None:
        """Nothing to update is still up to date, so the caller may proceed."""
        with _mock_update_vaults_state(is_meta_vault=True) as mocks:
            result = await update_vaults_state(vaults=[VAULT_1])
        assert result is True
        mocks['tx_aggregate'].assert_not_awaited()

    async def test_skips_when_not_harvestable(self) -> None:
        """can_harvest returns no harvest params, so there is nothing to update."""
        with _mock_update_vaults_state(harvest_params=None) as mocks:
            result = await update_vaults_state(vaults=[VAULT_1])
        assert result is True
        mocks['tx_aggregate'].assert_not_awaited()

    async def test_batches_calls_into_chunks(self) -> None:
        """Calls are split into MULTICALL_CHUNK_SIZE-sized transactions."""
        with _mock_update_vaults_state(chunk_size=1) as mocks:
            await update_vaults_state(vaults=[VAULT_1, VAULT_2])
        # Two vaults, chunk size 1 → one multicall transaction per vault.
        assert mocks['tx_aggregate'].await_count == 2
        for call in mocks['tx_aggregate'].await_args_list:
            assert len(call.args[0]) == 1

    async def test_stops_on_unconfirmed_receipt(self) -> None:
        """An unconfirmed multicall stops the loop without raising, leaving the
        remaining chunks unsubmitted, and reports stale state to the caller."""
        with _mock_update_vaults_state(tx_status=0, chunk_size=1) as mocks:
            result = await update_vaults_state(vaults=[VAULT_1, VAULT_2])
        assert result is False
        # First chunk was not confirmed, so the second chunk is never submitted.
        assert mocks['tx_aggregate'].await_count == 1

    async def test_stops_on_send_failure(self) -> None:
        """An error while submitting stops the loop without raising."""
        with _mock_update_vaults_state(send_exception=Exception('boom'), chunk_size=1) as mocks:
            result = await update_vaults_state(vaults=[VAULT_1, VAULT_2])
        assert result is False
        assert mocks['tx_aggregate'].await_count == 1


# --- Helpers ---


@contextmanager
def _mock_update_vaults_state(
    is_meta_vault: bool = False,
    harvest_params: object = object(),
    tx_status: int = 1,
    chunk_size: int | None = None,
    send_exception: BaseException | None = None,
) -> Iterator[dict[str, AsyncMock]]:
    """Mock setup for update_vaults_state tests. VaultContract, harvest params and
    the multicall contract are all stubbed so only the orchestration logic is
    exercised. ``harvest_params=None`` models a vault that can_harvest filtered
    out. ``tx_status=0`` models an unconfirmed multicall tx, i.e. ``tx_aggregate``
    returning no receipt, while ``send_exception`` makes ``tx_aggregate`` raise.
    ``chunk_size`` overrides MULTICALL_CHUNK_SIZE."""
    vault_contract = MagicMock()
    vault_contract.contract_address = VAULT_1
    vault_contract.get_update_state_call = MagicMock(return_value='0xdeadbeef')

    tx_receipt = {'status': 1, 'transactionHash': HexBytes(b'\xab' * 32)} if tx_status else None
    if send_exception is not None:
        tx_aggregate = AsyncMock(side_effect=send_exception)
    else:
        tx_aggregate = AsyncMock(return_value=tx_receipt)
    mock_multicall = MagicMock()
    mock_multicall.tx_aggregate = tx_aggregate

    def harvest_params_for(vaults: list, _block: BlockNumber | None = None) -> dict:
        return {vault: harvest_params for vault in vaults}

    with (
        patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=is_meta_vault)),
        patch(f'{MODULE}.VaultContract', return_value=vault_contract),
        patch(
            f'{MODULE}.get_multiple_harvest_params',
            new=AsyncMock(side_effect=harvest_params_for),
        ),
        patch(f'{MODULE}.multicall_contract', new=mock_multicall),
        patch(f'{MODULE}.MULTICALL_CHUNK_SIZE', new=chunk_size if chunk_size is not None else 20),
    ):
        yield {'tx_aggregate': tx_aggregate}


@contextmanager
def _mock_tx_redeem_position(
    tx_status: int = 1,
    send_exception: BaseException | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for tx_redeem_position tests.

    ``send_exception`` makes ``tx_manager.transact`` raise; otherwise it returns a
    receipt with the given ``tx_status``, or ``None`` when ``tx_status`` is 0
    (mirrors ``TransactionManager`` returning no receipt for a reverted tx).
    """
    tx_receipt = (
        {
            'status': tx_status,
            'blockNumber': BlockNumber(456),
            'transactionHash': HexBytes(b'\xab' * 32),
        }
        if tx_status
        else None
    )

    mock_tx_manager = MagicMock()
    if send_exception is not None:
        mock_tx_manager.transact = AsyncMock(side_effect=send_exception)
    else:
        mock_tx_manager.transact = AsyncMock(return_value=tx_receipt)

    synced_mock = AsyncMock()
    with (
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(f'{MODULE}.tx_manager', new=mock_tx_manager),
        patch(f'{MODULE}.wait_for_execution_endpoints_synced', new=synced_mock),
    ):
        mock_redeemer.contract.functions.redeemOsTokenPositions = MagicMock()
        yield {
            'redeemer': mock_redeemer,
            'tx_manager': mock_tx_manager,
            'wait_for_execution_endpoints_synced': synced_mock,
        }


@contextmanager
def _mock_simulate_redeem_position(
    call_exception: BaseException | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for simulate_redeem_position tests.

    ``call_exception`` makes the simulated ``.call()`` raise; otherwise it succeeds.
    """
    if call_exception is not None:
        call_mock = AsyncMock(side_effect=call_exception)
    else:
        call_mock = AsyncMock(return_value=None)

    tx_function = MagicMock()
    tx_function.call = call_mock

    with patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer:
        mock_redeemer.contract.functions.redeemOsTokenPositions = MagicMock(
            return_value=tx_function
        )
        yield {
            'redeemer': mock_redeemer,
            'call': call_mock,
        }
