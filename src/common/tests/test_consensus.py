import itertools
from unittest import mock

import pytest
from web3.types import BlockNumber

from src.common.consensus import wait_execution_catch_up_latest_head
from src.common.exceptions import ExecutionBehindConsensusError


@pytest.mark.usefixtures('fake_settings')
class TestWaitExecutionCatchUpLatestHead:
    async def test_returns_immediately_when_execution_is_up_to_date(self):
        execution_client = _execution_client_with_block_numbers(100)

        with mock.patch('src.common.consensus.execution_client', execution_client):
            await wait_execution_catch_up_latest_head(BlockNumber(100))

        assert execution_client.eth.get_block_number.await_count == 1

    async def test_waits_until_execution_imports_the_block(self):
        execution_client = _execution_client_with_block_numbers(99, 99, 100)

        with mock.patch('src.common.consensus.execution_client', execution_client), mock.patch(
            'src.common.consensus.EXECUTION_HEAD_SYNC_POLL_INTERVAL', 0
        ):
            await wait_execution_catch_up_latest_head(BlockNumber(100))

        assert execution_client.eth.get_block_number.await_count == 3

    async def test_raises_when_execution_does_not_catch_up_in_time(self):
        execution_client = mock.Mock()
        execution_client.eth.get_block_number = mock.AsyncMock(return_value=98)
        # first call sets the deadline, every later call is past it
        monotonic = itertools.chain([0], itertools.repeat(1000))

        with mock.patch('src.common.consensus.execution_client', execution_client), mock.patch(
            'src.common.consensus.EXECUTION_HEAD_SYNC_POLL_INTERVAL', 0
        ), mock.patch('src.common.consensus.time.monotonic', side_effect=monotonic):
            with pytest.raises(ExecutionBehindConsensusError) as error:
                await wait_execution_catch_up_latest_head(BlockNumber(100))

        assert error.value.execution_block_number == 98
        assert error.value.consensus_block_number == 100


def _execution_client_with_block_numbers(*block_numbers: int) -> mock.Mock:
    client = mock.Mock()
    client.eth.get_block_number = mock.AsyncMock(side_effect=list(block_numbers))
    return client
