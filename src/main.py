import asyncio
import logging
import time

import backoff
from eth_typing import BlockNumber
from sw_utils import EventScanner, InterruptHandler

import src
from src.common.accounts import operator_account
from src.common.clients import execution_client
from src.config.settings import (
    DEFAULT_RETRY_TIME,
    LOG_LEVEL,
    NETWORK,
    NETWORK_CONFIG,
    SENTRY_DSN,
)
from src.startup_check import startup_checks
from src.validators.database import setup as validators_db_setup
from src.validators.execution import NetworkValidatorsProcessor
from src.validators.tasks import load_genesis_validators, register_validators
from src.validators.utils import load_deposit_data, load_keystores

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%m-%d %H:%M',
    level=LOG_LEVEL,
)
logging.getLogger('backoff').addHandler(logging.StreamHandler())

logger = logging.getLogger(__name__)


@backoff.on_exception(backoff.expo, Exception, max_time=DEFAULT_RETRY_TIME)
async def get_safe_block_number() -> BlockNumber:
    """Fetches the fork safe block number."""
    block_number = await execution_client.eth.block_number  # type: ignore
    return BlockNumber(max(block_number - NETWORK_CONFIG.CONFIRMATION_BLOCKS, 0))


async def main() -> None:
    logger.info('Version %s', src.__version__)

    await startup_checks()

    validators_db_setup()

    # load genesis validators for some networks
    await load_genesis_validators()

    # load keystores
    keystores = load_keystores()

    # load deposit data
    deposit_data = await load_deposit_data()

    # start operator tasks
    interrupt_handler = InterruptHandler()

    # periodically scan network validator updates
    network_validators_processor = NetworkValidatorsProcessor()
    network_validators_scanner = EventScanner(network_validators_processor)

    while not interrupt_handler.exit:
        start_time = time.time()
        to_block = await get_safe_block_number()

        # process new network validators
        await network_validators_scanner.process_new_events(to_block)

        # check and register new validators
        await register_validators(keystores, deposit_data)

        block_processing_time = time.time() - start_time
        sleep_time = max(int(NETWORK_CONFIG.SECONDS_PER_BLOCK) - int(block_processing_time), 0)
        await asyncio.sleep(sleep_time)


if __name__ == '__main__':
    if SENTRY_DSN:
        import sentry_sdk
        from sentry_sdk.integrations.logging import ignore_logger

        sentry_sdk.init(SENTRY_DSN, traces_sample_rate=0.1)
        sentry_sdk.set_tag('network', NETWORK)
        sentry_sdk.set_tag('operator', operator_account.address)
        ignore_logger('backoff')

    asyncio.run(main())
