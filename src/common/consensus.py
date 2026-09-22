import asyncio
import time

from eth_typing import BlockNumber
from sw_utils import get_chain_finalized_head as sw_get_chain_finalized_head
from sw_utils.consensus import get_chain_epoch_head as sw_get_chain_epoch_head
from sw_utils.consensus import get_chain_justified_head as sw_get_chain_justified_head
from sw_utils.consensus import get_chain_latest_head as sw_get_chain_latest_head
from sw_utils.typings import ChainHead

from src.common.clients import consensus_client, execution_client
from src.common.exceptions import ExecutionBehindConsensusError
from src.config.settings import settings

EXECUTION_HEAD_SYNC_POLL_INTERVAL = 0.1


async def get_chain_finalized_head() -> ChainHead:
    return await sw_get_chain_finalized_head(
        consensus_client=consensus_client, slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH
    )


async def get_chain_justified_head() -> ChainHead:
    return await sw_get_chain_justified_head(
        consensus_client=consensus_client, slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH
    )


async def get_chain_latest_head() -> ChainHead:
    """
    Fetches the latest consensus head and waits until the execution client has imported
    the matching execution block.

    The consensus client serves a new head as soon as the beacon block is processed, while
    the execution client exposes the block only after executing it. Querying execution state
    at that block number in between fails with `header not found`.
    """
    chain_head = await sw_get_chain_latest_head(
        consensus_client=consensus_client, slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH
    )
    await wait_execution_catch_up_latest_head(chain_head.block_number)
    return chain_head


async def wait_execution_catch_up_latest_head(block_number: BlockNumber) -> None:
    """
    Waits up to a single slot for the execution client to import the given block.
    Raises `ExecutionBehindConsensusError` if it does not catch up in time.
    """
    deadline = time.monotonic() + settings.network_config.SECONDS_PER_BLOCK
    while True:
        execution_block_number = await execution_client.eth.get_block_number()
        if execution_block_number >= block_number:
            return

        if time.monotonic() >= deadline:
            raise ExecutionBehindConsensusError(
                execution_block_number=execution_block_number,
                consensus_block_number=block_number,
            )
        await asyncio.sleep(EXECUTION_HEAD_SYNC_POLL_INTERVAL)


async def get_chain_epoch_head(epoch: int) -> ChainHead:
    return await sw_get_chain_epoch_head(
        epoch=epoch,
        consensus_client=consensus_client,
        execution_client=execution_client,
        slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH,
    )
