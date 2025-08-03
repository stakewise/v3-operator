from unittest.mock import AsyncMock

import pytest
from web3 import Web3

from src.withdrawals.assets import (
    _get_pending_partial_withdrawals_amount,
    consensus_client,
)


@pytest.mark.asyncio
async def test_get_pending_partial_withdrawals():
    consensus_client.get_pending_partial_withdrawals = AsyncMock(return_value=[])
    result = await _get_pending_partial_withdrawals_amount(['1', '2'], 12345)
    assert result == Web3.to_wei(0, 'gwei')

    # sums amounts for matching validator indexes
    consensus_client.get_pending_partial_withdrawals = AsyncMock(
        return_value=[
            {'validator_index': '1', 'amount': '10'},
            {'validator_index': '2', 'amount': '20'},
        ]
    )
    result = await _get_pending_partial_withdrawals_amount(['1', '2'], 12345)
    assert result == Web3.to_wei(30, 'gwei')

    # ignores non matching validator indexes
    consensus_client.get_pending_partial_withdrawals = AsyncMock(
        return_value=[
            {'validator_index': '3', 'amount': '10'},
            {'validator_index': '4', 'amount': '20'},
        ]
    )
    result = await _get_pending_partial_withdrawals_amount(['1', '2'], 12345)
    assert result == Web3.to_wei(0, 'gwei')

    # handles empty validator indexes list
    consensus_client.get_pending_partial_withdrawals = AsyncMock(
        return_value=[
            {'validator_index': '1', 'amount': '10'},
            {'validator_index': '2', 'amount': '20'},
        ]
    )
    result = await _get_pending_partial_withdrawals_amount([], 12345)
    assert result == Web3.to_wei(0, 'gwei')

    # handles large amounts correctly
    consensus_client.get_pending_partial_withdrawals = AsyncMock(
        return_value=[
            {'validator_index': '1', 'amount': str(2**60)},
            {'validator_index': '2', 'amount': str(2**60)},
        ]
    )
    result = await _get_pending_partial_withdrawals_amount(['1', '2'], 12345)
    assert result == Web3.to_wei(2**61, 'gwei')
