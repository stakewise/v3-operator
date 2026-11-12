import asyncio
import logging
import time

from sw_utils import ExecutionBehindConsensusError
from sw_utils import get_chain_finalized_head as sw_get_chain_finalized_head
from sw_utils.consensus import get_chain_epoch_head as sw_get_chain_epoch_head
from sw_utils.consensus import get_chain_latest_head as sw_get_chain_latest_head
from sw_utils.typings import ChainHead

from src.common.clients import consensus_client, execution_client
from src.config.settings import settings

logger = logging.getLogger(__name__)

EXECUTION_HEAD_SYNC_POLL_INTERVAL = 0.5


async def wait_for_chain_finalized_head() -> ChainHead:
    while True:
        try:
            return await get_chain_finalized_head()
        except ExecutionBehindConsensusError as e:
            logger.warning('The execution client is behind the consensus client: %s', e)
            await asyncio.sleep(settings.network_config.SECONDS_PER_BLOCK)


async def get_chain_finalized_head() -> ChainHead:
    """Raises `ExecutionBehindConsensusError` if the execution client lacks the head block."""
    chain_head = await sw_get_chain_finalized_head(
        consensus_client=consensus_client,
        execution_client=execution_client,
        network_config=settings.network_config,
    )
    await _check_execution_has_block(chain_head)
    return chain_head


async def get_chain_latest_head() -> ChainHead:
    """
    Fetches the latest consensus head whose execution block is available.

    The consensus client serves a new head as soon as the beacon block is processed, while
    the execution client exposes the block only after executing it. Querying execution state
    at that block number in between fails with `header not found`, so the head is refetched
    for up to one slot before `ExecutionBehindConsensusError` is re-raised.
    """
    deadline = time.monotonic() + settings.network_config.SECONDS_PER_BLOCK
    while True:
        try:
            chain_head = await sw_get_chain_latest_head(
                consensus_client=consensus_client,
                execution_client=execution_client,
                network_config=settings.network_config,
            )
            await _check_execution_has_block(chain_head)
        except ExecutionBehindConsensusError:
            if time.monotonic() >= deadline:
                raise
            await asyncio.sleep(EXECUTION_HEAD_SYNC_POLL_INTERVAL)
        else:
            return chain_head


async def get_chain_epoch_head(epoch: int) -> ChainHead:
    return await sw_get_chain_epoch_head(
        epoch=epoch,
        consensus_client=consensus_client,
        execution_client=execution_client,
        network_config=settings.network_config,
    )


async def _check_execution_has_block(chain_head: ChainHead) -> None:
    # sw-utils already resolved the execution block by hash post-fork
    if chain_head.slot >= settings.network_config.GLAMSTERDAM_SLOT:
        return

    execution_block_number = await execution_client.eth.get_block_number()
    if execution_block_number < chain_head.block_number:
        raise ExecutionBehindConsensusError(
            'The execution client has not imported the consensus head block yet: '
            f'execution block {execution_block_number}, '
            f'consensus block {chain_head.block_number}'
        )
