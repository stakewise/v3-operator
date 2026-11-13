import itertools
from typing import Generator
from unittest import mock

import pytest
from sw_utils import ExecutionBehindConsensusError
from sw_utils.typings import ChainHead

from src.common.clients import consensus_client, execution_client
from src.common.consensus import (
    EXECUTION_HEAD_SYNC_POLL_INTERVAL,
    _check_execution_has_block,
    get_chain_epoch_head,
    get_chain_finalized_head,
    get_chain_latest_head,
    wait_for_chain_finalized_head,
)
from src.common.tests.factories import create_chain_head
from src.config.settings import settings

EXECUTION_BEHIND_MESSAGE = (
    'The execution client has not imported the consensus head block yet: '
    'execution block 98, consensus block 100'
)


@pytest.fixture
def pre_fork_head(fake_settings) -> ChainHead:
    return create_chain_head(slot=settings.network_config.GLAMSTERDAM_SLOT - 1, block_number=100)


@pytest.fixture
def post_fork_head(fake_settings) -> ChainHead:
    return create_chain_head(slot=settings.network_config.GLAMSTERDAM_SLOT, block_number=100)


@pytest.fixture
def mocked_execution_block_number() -> Generator[mock.AsyncMock, None, None]:
    get_block_number = mock.AsyncMock(return_value=98)
    with mock.patch(
        'src.common.consensus.execution_client',
        mock.Mock(eth=mock.Mock(get_block_number=get_block_number)),
    ):
        yield get_block_number


@pytest.fixture
def mocked_sleep() -> Generator[mock.AsyncMock, None, None]:
    with mock.patch('src.common.consensus.asyncio.sleep', new_callable=mock.AsyncMock) as sleep:
        yield sleep


@pytest.fixture
def mocked_check_execution_has_block() -> Generator[mock.AsyncMock, None, None]:
    with mock.patch(
        'src.common.consensus._check_execution_has_block', new_callable=mock.AsyncMock
    ) as check:
        yield check


@pytest.fixture
def mocked_sw_finalized_head() -> Generator[mock.AsyncMock, None, None]:
    with mock.patch(
        'src.common.consensus.sw_get_chain_finalized_head', new_callable=mock.AsyncMock
    ) as sw_get_chain_finalized_head:
        yield sw_get_chain_finalized_head


@pytest.fixture
def mocked_sw_latest_head() -> Generator[mock.AsyncMock, None, None]:
    with mock.patch(
        'src.common.consensus.sw_get_chain_latest_head', new_callable=mock.AsyncMock
    ) as sw_get_chain_latest_head:
        yield sw_get_chain_latest_head


@pytest.fixture
def mocked_sw_epoch_head() -> Generator[mock.AsyncMock, None, None]:
    with mock.patch(
        'src.common.consensus.sw_get_chain_epoch_head', new_callable=mock.AsyncMock
    ) as sw_get_chain_epoch_head:
        yield sw_get_chain_epoch_head


@pytest.fixture
def expired_deadline() -> Generator[None, None, None]:
    # The first reading sets the deadline, every later one is past it.
    monotonic = itertools.chain([0], itertools.repeat(1000))
    with mock.patch('src.common.consensus.time', mock.Mock(monotonic=lambda: next(monotonic))):
        yield


@pytest.mark.usefixtures('fake_settings', 'mocked_check_execution_has_block')
class TestChainHeadWrappers:
    async def test_get_chain_finalized_head(self, mocked_sw_finalized_head: mock.AsyncMock):
        chain_head = await get_chain_finalized_head()

        assert chain_head == mocked_sw_finalized_head.return_value
        mocked_sw_finalized_head.assert_awaited_once_with(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=settings.network_config,
        )

    async def test_get_chain_latest_head(self, mocked_sw_latest_head: mock.AsyncMock):
        chain_head = await get_chain_latest_head()

        assert chain_head == mocked_sw_latest_head.return_value
        mocked_sw_latest_head.assert_awaited_once_with(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=settings.network_config,
        )

    async def test_get_chain_epoch_head(
        self, mocked_sw_epoch_head: mock.AsyncMock, mocked_check_execution_has_block: mock.AsyncMock
    ):
        chain_head = await get_chain_epoch_head(123)

        assert chain_head == mocked_sw_epoch_head.return_value
        mocked_check_execution_has_block.assert_awaited_once_with(chain_head)
        mocked_sw_epoch_head.assert_awaited_once_with(
            epoch=123,
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=settings.network_config,
        )


class TestCheckExecutionHasBlock:
    async def test_pre_fork_passes_when_execution_has_block(
        self, pre_fork_head: ChainHead, mocked_execution_block_number: mock.AsyncMock
    ):
        mocked_execution_block_number.return_value = 100

        await _check_execution_has_block(pre_fork_head)

        mocked_execution_block_number.assert_awaited_once()

    async def test_pre_fork_raises_when_execution_is_behind(
        self, pre_fork_head: ChainHead, mocked_execution_block_number: mock.AsyncMock
    ):
        with pytest.raises(ExecutionBehindConsensusError) as error:
            await _check_execution_has_block(pre_fork_head)

        assert str(error.value) == EXECUTION_BEHIND_MESSAGE

    async def test_post_fork_skips_execution_call(
        self, post_fork_head: ChainHead, mocked_execution_block_number: mock.AsyncMock
    ):
        await _check_execution_has_block(post_fork_head)

        mocked_execution_block_number.assert_not_awaited()


@pytest.mark.usefixtures('mocked_execution_block_number')
class TestGetChainFinalizedHead:
    async def test_raises_when_execution_is_behind_pre_fork(
        self, pre_fork_head: ChainHead, mocked_sw_finalized_head: mock.AsyncMock
    ):
        mocked_sw_finalized_head.return_value = pre_fork_head

        with pytest.raises(ExecutionBehindConsensusError, match='execution block 98'):
            await get_chain_finalized_head()

    async def test_returns_head_post_fork(
        self, post_fork_head: ChainHead, mocked_sw_finalized_head: mock.AsyncMock
    ):
        mocked_sw_finalized_head.return_value = post_fork_head

        assert await get_chain_finalized_head() == post_fork_head


@pytest.mark.usefixtures('mocked_execution_block_number')
class TestGetChainEpochHead:
    async def test_raises_when_execution_is_behind_pre_fork(
        self, pre_fork_head: ChainHead, mocked_sw_epoch_head: mock.AsyncMock
    ):
        mocked_sw_epoch_head.return_value = pre_fork_head

        with pytest.raises(ExecutionBehindConsensusError, match='execution block 98'):
            await get_chain_epoch_head(123)

    async def test_returns_head_post_fork(
        self, post_fork_head: ChainHead, mocked_sw_epoch_head: mock.AsyncMock
    ):
        mocked_sw_epoch_head.return_value = post_fork_head

        assert await get_chain_epoch_head(123) == post_fork_head


@pytest.mark.usefixtures('mocked_execution_block_number', 'mocked_sleep')
class TestGetChainLatestHead:
    async def test_retries_until_execution_has_the_block(
        self,
        pre_fork_head: ChainHead,
        mocked_sw_latest_head: mock.AsyncMock,
        mocked_execution_block_number: mock.AsyncMock,
        mocked_sleep: mock.AsyncMock,
    ):
        mocked_sw_latest_head.return_value = pre_fork_head
        mocked_execution_block_number.side_effect = [98, 99, 100]

        assert await get_chain_latest_head() == pre_fork_head

        assert mocked_sw_latest_head.await_count == 3
        assert mocked_sleep.await_args_list == [mock.call(EXECUTION_HEAD_SYNC_POLL_INTERVAL)] * 2

    async def test_retries_when_sw_utils_raises_post_fork(
        self,
        post_fork_head: ChainHead,
        mocked_sw_latest_head: mock.AsyncMock,
        mocked_sleep: mock.AsyncMock,
    ):
        mocked_sw_latest_head.side_effect = [
            ExecutionBehindConsensusError('block is not available'),
            post_fork_head,
        ]

        assert await get_chain_latest_head() == post_fork_head

        assert mocked_sw_latest_head.await_count == 2
        mocked_sleep.assert_awaited_once_with(EXECUTION_HEAD_SYNC_POLL_INTERVAL)

    @pytest.mark.usefixtures('expired_deadline')
    async def test_raises_after_deadline(
        self,
        pre_fork_head: ChainHead,
        mocked_sw_latest_head: mock.AsyncMock,
        mocked_sleep: mock.AsyncMock,
    ):
        mocked_sw_latest_head.return_value = pre_fork_head

        with pytest.raises(ExecutionBehindConsensusError) as error:
            await get_chain_latest_head()

        assert str(error.value) == EXECUTION_BEHIND_MESSAGE
        assert mocked_sw_latest_head.await_count == 1
        mocked_sleep.assert_not_awaited()


@pytest.mark.usefixtures('fake_settings', 'mocked_sleep')
class TestWaitForChainFinalizedHead:
    async def test_retries_while_execution_is_behind(
        self, mocked_sleep: mock.AsyncMock, post_fork_head: ChainHead
    ):
        with mock.patch(
            'src.common.consensus.get_chain_finalized_head',
            new_callable=mock.AsyncMock,
            side_effect=[
                ExecutionBehindConsensusError('block is not available'),
                ExecutionBehindConsensusError('block is not available'),
                post_fork_head,
            ],
        ) as get_head:
            assert await wait_for_chain_finalized_head() == post_fork_head

        assert get_head.await_count == 3
        assert (
            mocked_sleep.await_args_list
            == [mock.call(settings.network_config.SECONDS_PER_BLOCK)] * 2
        )

    async def test_propagates_other_errors(self, mocked_sleep: mock.AsyncMock):
        with mock.patch(
            'src.common.consensus.get_chain_finalized_head',
            new_callable=mock.AsyncMock,
            side_effect=RuntimeError('boom'),
        ):
            with pytest.raises(RuntimeError, match='boom'):
                await wait_for_chain_finalized_head()

        mocked_sleep.assert_not_awaited()
