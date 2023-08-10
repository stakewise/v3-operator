import asyncio
import logging
import time
from pathlib import Path

from eth_typing import BlockNumber
from web3 import Web3
from web3.types import Wei

from src.common.clients import consensus_client, execution_client
from src.config.settings import settings

logger = logging.getLogger(__name__)

WAD = Web3.to_wei(1, 'ether')
MGNO_RATE = Web3.to_wei(32, 'ether')


def convert_to_gno(mgno_amount: Wei) -> Wei:
    """Converts mGNO to GNO."""
    return Wei(mgno_amount * WAD // MGNO_RATE)


def get_build_version() -> str | None:
    path = Path(__file__).parents[1].joinpath('GIT_SHA')
    if not path.exists():
        return None

    with path.open(encoding='utf-8') as fh:
        return fh.read().strip()


def log_verbose(e: Exception):
    if settings.verbose:
        logger.exception(e)
    else:
        logger.error(e)


async def wait_block_finalization(block_number: BlockNumber | None = None):
    block_number = block_number or await execution_client.eth.get_block_number()
    chain_head = None
    sleep_time = 0.0

    while not chain_head or chain_head.execution_block < block_number:
        await asyncio.sleep(sleep_time)
        start = time.time()

        chain_head = await consensus_client.get_chain_finalized_head()

        elapsed = time.time() - start
        sleep_time = float(settings.network_config.SECONDS_PER_BLOCK) - elapsed
