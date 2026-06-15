from contextlib import contextmanager
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber, ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Wei

from src.redemptions.execution import (
    simulate_redeem_position,
    tx_process_exit_queue,
    tx_redeem_position,
)
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.typings import OsTokenPosition

MODULE = 'src.redemptions.execution'

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
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
        mocks['transaction_gas_wrapper'].assert_awaited_once()
        mocks['client'].eth.wait_for_transaction_receipt.assert_awaited_once()
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

    @pytest.mark.parametrize('exc_class', [Web3Exception, RuntimeError, ValueError])
    async def test_tx_build_failure_returns_false(self, exc_class: type[Exception]) -> None:
        """Each caught exception during tx build/send returns False."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_tx_redeem_position(send_exception=exc_class('boom')) as mocks:
            result = await tx_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is False
        # Receipt is never awaited when the build step raised
        mocks['client'].eth.wait_for_transaction_receipt.assert_not_awaited()

    async def test_unexpected_exception_propagates(self) -> None:
        """Exceptions outside the (Web3Exception, RuntimeError, ValueError) catch list propagate."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_tx_redeem_position(send_exception=KeyError('boom')):
            with pytest.raises(KeyError):
                await tx_redeem_position(
                    position=position,
                    tree=make_tree([position]),
                )


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

    @pytest.mark.parametrize('exc_class', [Web3Exception, RuntimeError, ValueError])
    async def test_call_failure_returns_false(self, exc_class: type[Exception]) -> None:
        """A failed simulation returns False without raising."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_simulate_redeem_position(call_exception=exc_class('boom')):
            result = await simulate_redeem_position(
                position=position,
                tree=make_tree([position]),
            )
        assert result is False


class TestTxProcessExitQueue:
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
            mock_redeemer.process_exit_queue = AsyncMock(return_value='0xabc')
            await tx_process_exit_queue()
            mock_redeemer.process_exit_queue.assert_called_once()


# --- Helpers ---


@contextmanager
def _mock_tx_redeem_position(
    tx_status: int = 1,
    send_exception: BaseException | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for tx_redeem_position tests.

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

    synced_mock = AsyncMock()
    with (
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(f'{MODULE}.transaction_gas_wrapper', new=gas_wrapper),
        patch(f'{MODULE}.execution_client', new=mock_client),
        patch(f'{MODULE}.wait_for_execution_endpoints_synced', new=synced_mock),
        patch(f'{MODULE}.settings') as mock_settings,
    ):
        mock_settings.execution_transaction_timeout = 120
        mock_redeemer.contract.functions.redeemOsTokenPositions = MagicMock()
        yield {
            'redeemer': mock_redeemer,
            'transaction_gas_wrapper': gas_wrapper,
            'client': mock_client,
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


def make_tree(
    positions: list[OsTokenPosition] | None = None, nonce: int = 5
) -> PositionsMerkleTree:
    return PositionsMerkleTree(positions or [make_position()], nonce)


def make_position(
    vault: ChecksumAddress = VAULT_1,
    owner: ChecksumAddress = OWNER_1,
    leaf_shares: int = 1000,
    processed_shares: int = 500,
    shares_to_redeem: int | None = None,
) -> OsTokenPosition:
    effective_shares_to_redeem = (
        shares_to_redeem if shares_to_redeem is not None else leaf_shares - processed_shares
    )
    return OsTokenPosition(
        vault=vault,
        owner=owner,
        leaf_shares=Wei(leaf_shares),
        index=0,
        processed_shares=Wei(processed_shares),
        shares_to_redeem=Wei(effective_shares_to_redeem),
    )
