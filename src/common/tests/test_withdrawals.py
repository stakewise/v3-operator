from unittest import mock

import pytest
from web3.types import Wei

from src.common.execution import fake_exponential
from src.common.tests.factories import create_chain_head
from src.common.withdrawals import get_withdrawal_request_fee, get_withdrawals_count


def test_fake_exponential_known_values():
    # hand-computed reference vectors for factor * approx(e^(numerator/denominator))
    assert fake_exponential(1, 0, 1) == 1
    assert fake_exponential(1, 1, 1) == 2
    assert fake_exponential(1, 2, 1) == 6


@pytest.mark.usefixtures('fake_settings')
class TestGetWithdrawalRequestFee:
    async def test_zero_excess_returns_min_execution_request_fee(self):
        with mock.patch(
            'src.common.withdrawals.get_execution_withdrawals_count',
            mock.AsyncMock(return_value=0),
        ), mock.patch('src.common.withdrawals.execution_client', _execution_client_with_excess(0)):
            fee = await get_withdrawal_request_fee(count=0, gap_count=0)

        assert fee == Wei(1)

    async def test_known_excess_matches_fake_exponential_formula(self):
        # previous_excess=15, count(2) + gap_count(0) = 2 -> excess = 15 + 2 - target(2) = 15
        # fake_exponential(MIN_EXECUTION_REQUEST_FEE=1, 15, EXECUTION_REQUEST_FEE_UPDATE_FRACTION=17) == 2
        with mock.patch(
            'src.common.withdrawals.get_execution_withdrawals_count',
            mock.AsyncMock(return_value=0),
        ), mock.patch('src.common.withdrawals.execution_client', _execution_client_with_excess(15)):
            fee = await get_withdrawal_request_fee(count=2, gap_count=0)

        assert fee == Wei(2)

    async def test_higher_count_yields_a_higher_or_equal_fee(self):
        with mock.patch(
            'src.common.withdrawals.get_execution_withdrawals_count',
            mock.AsyncMock(return_value=0),
        ), mock.patch(
            'src.common.withdrawals.execution_client', _execution_client_with_excess(100)
        ):
            low_count_fee = await get_withdrawal_request_fee(count=1)
            high_count_fee = await get_withdrawal_request_fee(count=5)

        assert high_count_fee >= low_count_fee


@pytest.mark.usefixtures('fake_settings')
class TestGetWithdrawalsCount:
    async def test_sums_consensus_list_length_and_execution_count(self):
        chain_head = create_chain_head()
        consensus_client_mock = mock.Mock(
            get_pending_partial_withdrawals=mock.AsyncMock(return_value=[{}, {}, {}])
        )

        with mock.patch(
            'src.common.withdrawals.get_execution_withdrawals_count',
            mock.AsyncMock(return_value=7),
        ), mock.patch('src.common.withdrawals.consensus_client', consensus_client_mock):
            result = await get_withdrawals_count(chain_head)

        assert result == 10


def _execution_client_with_excess(previous_excess: int) -> mock.Mock:
    client = mock.Mock()
    client.eth.get_storage_at = mock.AsyncMock(
        return_value=previous_excess.to_bytes(32, byteorder='big')
    )
    return client
