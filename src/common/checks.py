import asyncio
import logging

from sw_utils import ChainHead, InterruptHandler

from src.common.clients import execution_client
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def wait_execution_catch_up_consensus(
    chain_head: ChainHead, interrupt_handler: InterruptHandler | None = None
) -> None:
    """
    Consider execution and consensus nodes are working independently of each other.
    Check execution node is synced to the consensus finalized block.
    """
    while True:
        if interrupt_handler and interrupt_handler.exit:
            return

        execution_block_number = await execution_client.eth.get_block_number()
        if execution_block_number >= chain_head.block_number:
            return

        logger.warning(
            'The execution client is behind the consensus client: '
            'execution block %d, consensus finalized block %d, distance %d blocks',
            execution_block_number,
            chain_head.block_number,
            chain_head.block_number - execution_block_number,
        )
        sleep_time = float(settings.network_config.SECONDS_PER_BLOCK)

        if interrupt_handler:
            await interrupt_handler.sleep(sleep_time)
        else:
            await asyncio.sleep(sleep_time)
