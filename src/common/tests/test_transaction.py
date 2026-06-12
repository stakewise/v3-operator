from math import ceil
from unittest import mock

import pytest
from hexbytes import HexBytes
from web3 import Web3
from web3.types import Wei

from src.common.transaction import REPLACEMENT_GAS_BUMP, TransactionManager

GWEI = Web3.to_wei(1, 'gwei')


@pytest.mark.usefixtures('fake_settings')
class TestTransactionManager:
    async def test_no_pending_uses_latest_nonce(self):
        transact = mock.AsyncMock(return_value=HexBytes('0x01'))
        ec, w, gm = _patch(
            latest_nonce=5, pending_nonce=5, gas_manager=_gas_manager(GWEI, GWEI // 2)
        )
        with ec, w, gm:
            manager = TransactionManager()
            tx_hash = await manager.transact(_tx_function(transact))

        assert tx_hash == HexBytes('0x01')
        params = transact.call_args.args[0]
        assert params['nonce'] == 5
        assert params['maxFeePerGas'] == GWEI
        assert params['maxPriorityFeePerGas'] == GWEI // 2

    async def test_pending_reuses_nonce_and_bumps_gas(self):
        manager = TransactionManager()

        # first submission records the gas used for nonce 5
        transact1 = mock.AsyncMock(return_value=HexBytes('0x01'))
        ec, w, gm = _patch(
            latest_nonce=5, pending_nonce=5, gas_manager=_gas_manager(GWEI, GWEI // 2)
        )
        with ec, w, gm:
            await manager.transact(_tx_function(transact1))

        # second submission sees a pending tx at nonce 5 -> replace it, bumped
        transact2 = mock.AsyncMock(return_value=HexBytes('0x02'))
        ec, w, gm = _patch(
            latest_nonce=5, pending_nonce=6, gas_manager=_gas_manager(GWEI, GWEI // 2)
        )
        with ec, w, gm:
            await manager.transact(_tx_function(transact2))

        params = transact2.call_args.args[0]
        assert params['nonce'] == 5  # same nonce, not 6
        assert params['maxFeePerGas'] == ceil(GWEI * REPLACEMENT_GAS_BUMP)
        assert params['maxPriorityFeePerGas'] == ceil((GWEI // 2) * REPLACEMENT_GAS_BUMP)

    async def test_retries_on_replacement_underpriced(self):
        underpriced = ValueError({'code': -32000, 'message': 'replacement transaction underpriced'})
        transact = mock.AsyncMock(side_effect=[underpriced, HexBytes('0x02')])
        ec, w, gm = _patch(
            latest_nonce=5, pending_nonce=6, gas_manager=_gas_manager(GWEI, GWEI // 2)
        )
        with ec, w, gm:
            manager = TransactionManager()
            tx_hash = await manager.transact(_tx_function(transact))

        assert tx_hash == HexBytes('0x02')
        assert transact.await_count == 2
        first = transact.call_args_list[0].args[0]
        second = transact.call_args_list[1].args[0]
        assert second['nonce'] == first['nonce'] == 5
        assert second['maxFeePerGas'] > first['maxFeePerGas']
        assert second['maxPriorityFeePerGas'] > first['maxPriorityFeePerGas']

    async def test_gas_capped_at_max_fee_per_gas(self):
        # high-priority returns far above the HOODI ceiling (10 gwei)
        huge = Web3.to_wei(100, 'gwei')
        cap = Web3.to_wei(10, 'gwei')
        transact = mock.AsyncMock(return_value=HexBytes('0x01'))
        ec, w, gm = _patch(latest_nonce=5, pending_nonce=5, gas_manager=_gas_manager(huge, huge))
        with ec, w, gm:
            manager = TransactionManager()
            await manager.transact(_tx_function(transact))

        params = transact.call_args.args[0]
        assert params['maxFeePerGas'] == cap
        assert params['maxPriorityFeePerGas'] <= params['maxFeePerGas']


def _gas_manager(max_fee: int, priority_fee: int) -> mock.Mock:
    manager = mock.Mock()
    manager.get_high_priority_tx_params = mock.AsyncMock(
        return_value={'maxFeePerGas': Wei(max_fee), 'maxPriorityFeePerGas': Wei(priority_fee)}
    )
    return manager


def _patch(latest_nonce: int, pending_nonce: int, gas_manager: mock.Mock):
    execution_client = mock.Mock()
    execution_client.eth.get_transaction_count = mock.AsyncMock(
        side_effect=[latest_nonce, pending_nonce]
    )
    wallet = mock.Mock()
    wallet.address = '0x' + '11' * 20
    return (
        mock.patch('src.common.transaction.execution_client', execution_client),
        mock.patch('src.common.transaction.wallet', wallet),
        mock.patch('src.common.transaction.build_gas_manager', return_value=gas_manager),
    )


def _tx_function(transact_mock: mock.AsyncMock) -> mock.Mock:
    tx_function = mock.Mock()
    tx_function.transact = transact_mock
    return tx_function
