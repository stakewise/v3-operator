from typing import Generator
from unittest import mock

import pytest

from src.common.clients import execution_client
from src.common.execution import get_payload_expected_withdrawals
from src.common.tests.factories import create_chain_head, create_withdrawal
from src.config.settings import settings


@pytest.fixture
def mocked_sw_payload_expected_withdrawals() -> Generator[mock.AsyncMock, None, None]:
    with mock.patch(
        'src.common.execution.sw_get_payload_expected_withdrawals', new_callable=mock.AsyncMock
    ) as sw_get_payload_expected_withdrawals:
        yield sw_get_payload_expected_withdrawals


@pytest.mark.usefixtures('fake_settings')
async def test_get_payload_expected_withdrawals(
    mocked_sw_payload_expected_withdrawals: mock.AsyncMock,
):
    chain_head = create_chain_head()
    withdrawals = [create_withdrawal(validator_index=1, amount=5)]
    mocked_sw_payload_expected_withdrawals.return_value = withdrawals

    assert await get_payload_expected_withdrawals(chain_head) == withdrawals

    mocked_sw_payload_expected_withdrawals.assert_awaited_once_with(
        execution_client=execution_client,
        chain_head=chain_head,
        network_config=settings.network_config,
    )
