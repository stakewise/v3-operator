import contextlib
from math import ceil
from unittest import mock

import pytest
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import TimeExhausted
from web3.types import Wei

from src.common.transaction import REPLACEMENT_GAS_BUMP, TransactionManager

GWEI = Web3.to_wei(1, 'gwei')


@pytest.mark.usefixtures('fake_settings')
class TestTransactionManager:
    async def test_no_pending_high_priority_uses_latest_nonce(self):
        transact = mock.AsyncMock(return_value=HexBytes('0x01'))
        with _patch(latest_nonce=5, pending_nonce=5, gas_manager=_gas_manager(GWEI, GWEI // 2)):
            manager = TransactionManager()
            receipt = await manager.transact(_tx_function(transact), high_priority=True)

        assert receipt is not None
        params = transact.call_args.args[0]
        assert params['nonce'] == 5
        assert params['maxFeePerGas'] == GWEI
        assert params['maxPriorityFeePerGas'] == GWEI // 2

    async def test_default_gas_skips_fee_fields(self):
        # high_priority=False with no pending tx submits with the node's default gas
        transact = mock.AsyncMock(return_value=HexBytes('0x01'))
        with _patch(latest_nonce=5, pending_nonce=5, gas_manager=_gas_manager(GWEI, GWEI // 2)):
            manager = TransactionManager()
            await manager.transact(_tx_function(transact))

        params = transact.call_args.args[0]
        assert params['nonce'] == 5
        assert 'maxFeePerGas' not in params
        assert 'maxPriorityFeePerGas' not in params

    async def test_default_gas_escalates_on_fee_too_low(self):
        fee_too_low = ValueError({'code': -32010})
        # every default-gas attempt is rejected, the final escalation succeeds
        transact = mock.AsyncMock(
            side_effect=[fee_too_low, fee_too_low, fee_too_low, HexBytes('0x02')]
        )
        with _patch(
            latest_nonce=5, pending_nonce=5, gas_manager=_gas_manager(GWEI, GWEI // 2)
        ), mock.patch('src.common.transaction.ATTEMPTS_WITH_DEFAULT_GAS', 3), mock.patch(
            'src.common.transaction.asyncio.sleep', mock.AsyncMock()
        ):
            manager = TransactionManager()
            receipt = await manager.transact(_tx_function(transact))

        assert receipt is not None
        # 3 default-gas attempts + 1 high-priority escalation
        assert transact.await_count == 4
        escalated = transact.call_args_list[-1].args[0]
        assert escalated['maxFeePerGas'] == GWEI
        assert escalated['maxPriorityFeePerGas'] == GWEI // 2

    async def test_pending_reuses_nonce_and_bumps_gas(self):
        manager = TransactionManager()

        # first submission records the gas used for nonce 5
        transact1 = mock.AsyncMock(return_value=HexBytes('0x01'))
        with _patch(latest_nonce=5, pending_nonce=5, gas_manager=_gas_manager(GWEI, GWEI // 2)):
            await manager.transact(_tx_function(transact1), high_priority=True)

        # second submission sees a pending tx at nonce 5 -> replace it, bumped
        transact2 = mock.AsyncMock(return_value=HexBytes('0x02'))
        with _patch(latest_nonce=5, pending_nonce=6, gas_manager=_gas_manager(GWEI, GWEI // 2)):
            await manager.transact(_tx_function(transact2))

        params = transact2.call_args.args[0]
        assert params['nonce'] == 5  # same nonce, not 6
        assert params['maxFeePerGas'] == ceil(GWEI * REPLACEMENT_GAS_BUMP)
        assert params['maxPriorityFeePerGas'] == ceil((GWEI // 2) * REPLACEMENT_GAS_BUMP)

    async def test_pending_skips_default_gas(self):
        # even without high_priority, a pending tx forces the high-priority path
        transact = mock.AsyncMock(return_value=HexBytes('0x02'))
        with _patch(latest_nonce=5, pending_nonce=6, gas_manager=_gas_manager(GWEI, GWEI // 2)):
            manager = TransactionManager()
            await manager.transact(_tx_function(transact))

        assert transact.await_count == 1
        params = transact.call_args.args[0]
        assert params['nonce'] == 5
        assert params['maxFeePerGas'] == GWEI

    async def test_reverted_receipt_returns_none(self):
        transact = mock.AsyncMock(return_value=HexBytes('0x01'))
        with _patch(
            latest_nonce=5,
            pending_nonce=5,
            gas_manager=_gas_manager(GWEI, GWEI // 2),
            status=0,
        ):
            manager = TransactionManager()
            receipt = await manager.transact(_tx_function(transact), high_priority=True)

        assert receipt is None

    async def test_receipt_timeout_returns_none(self):
        # the receipt wait times out -> the tx is left pending and transact returns None
        # so the next run can detect and replace it
        transact = mock.AsyncMock(return_value=HexBytes('0x01'))
        with _patch(
            latest_nonce=5,
            pending_nonce=5,
            gas_manager=_gas_manager(GWEI, GWEI // 2),
            receipt_side_effect=TimeExhausted(),
        ):
            manager = TransactionManager()
            receipt = await manager.transact(_tx_function(transact), high_priority=True)

        assert receipt is None
        # the transaction was broadcast even though no receipt arrived
        transact.assert_awaited_once()

    async def test_gas_capped_at_max_fee_per_gas(self):
        # high-priority returns far above the HOODI ceiling (10 gwei)
        huge = Web3.to_wei(100, 'gwei')
        cap = Web3.to_wei(10, 'gwei')
        transact = mock.AsyncMock(return_value=HexBytes('0x01'))
        with _patch(latest_nonce=5, pending_nonce=5, gas_manager=_gas_manager(huge, huge)):
            manager = TransactionManager()
            await manager.transact(_tx_function(transact), high_priority=True)

        params = transact.call_args.args[0]
        assert params['maxFeePerGas'] == cap
        assert params['maxPriorityFeePerGas'] <= params['maxFeePerGas']


def _gas_manager(max_fee: int, priority_fee: int) -> mock.Mock:
    manager = mock.Mock()
    manager.get_high_priority_tx_params = mock.AsyncMock(
        return_value={'maxFeePerGas': Wei(max_fee), 'maxPriorityFeePerGas': Wei(priority_fee)}
    )
    return manager


@contextlib.contextmanager
def _patch(
    latest_nonce: int,
    pending_nonce: int,
    gas_manager: mock.Mock,
    status: int = 1,
    receipt_side_effect: Exception | None = None,
):
    execution_client = mock.Mock()
    execution_client.eth.get_transaction_count = mock.AsyncMock(
        side_effect=[latest_nonce, pending_nonce]
    )
    if receipt_side_effect is not None:
        execution_client.eth.wait_for_transaction_receipt = mock.AsyncMock(
            side_effect=receipt_side_effect
        )
    else:
        execution_client.eth.wait_for_transaction_receipt = mock.AsyncMock(
            return_value={
                'status': status,
                'transactionHash': HexBytes('0xab'),
                'blockNumber': 1,
            }
        )
    wallet = mock.Mock()
    wallet.address = '0x' + '11' * 20
    with mock.patch('src.common.transaction.execution_client', execution_client), mock.patch(
        'src.common.transaction.wallet', wallet
    ), mock.patch('src.common.transaction.build_gas_manager', return_value=gas_manager), mock.patch(
        'src.common.transaction.is_alchemy_used', return_value=False
    ):
        yield


def _tx_function(transact_mock: mock.AsyncMock) -> mock.Mock:
    tx_function = mock.Mock()
    tx_function.transact = transact_mock
    return tx_function
