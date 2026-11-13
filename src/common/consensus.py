"""
Every `ChainHead` returned here has its execution block imported by the execution client,
so execution state can be queried at `chain_head.block_number`.
Otherwise `ExecutionBehindConsensusError` is raised.

The consensus client serves a head before the execution client has executed its block.
Pre-Glamsterdam this is checked against the execution client's latest block number,
post-Glamsterdam sw-utils fetches the block by hash, which already guarantees it.
"""

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
    """Retries `get_chain_finalized_head` until the execution client catches up."""
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
    """Retries for up to one slot before re-raising `ExecutionBehindConsensusError`."""
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
    """Raises `ExecutionBehindConsensusError` if the execution client lacks the head block."""
    chain_head = await sw_get_chain_epoch_head(
        epoch=epoch,
        consensus_client=consensus_client,
        execution_client=execution_client,
        network_config=settings.network_config,
    )
    await _check_execution_has_block(chain_head)
    return chain_head


async def _check_execution_has_block(chain_head: ChainHead) -> None:
    # Post-fork sw-utils resolves the block through the execution client, see module docstring.
    if chain_head.slot >= settings.network_config.GLAMSTERDAM_SLOT:
        return

    execution_block_number = await execution_client.eth.get_block_number()
    if execution_block_number < chain_head.block_number:
        raise ExecutionBehindConsensusError(
            'The execution client has not imported the consensus head block yet: '
            f'execution block {execution_block_number}, '
            f'consensus block {chain_head.block_number}'
        )
