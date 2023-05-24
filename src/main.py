import asyncio
import logging
import os
import ssl
import sys
import time
from multiprocessing import freeze_support

from sw_utils import EventScanner, InterruptHandler

import src
from src.common.accounts import operator_account
from src.config.settings import LOG_LEVEL, NETWORK, NETWORK_CONFIG, SENTRY_DSN
from src.exits.tasks import update_exit_signatures
from src.startup_check import startup_checks
from src.utils import get_build_version, log_verbose
from src.validators.consensus import get_chain_finalized_head
from src.validators.database import setup as validators_db_setup
from src.validators.execution import NetworkValidatorsProcessor
from src.validators.tasks import load_genesis_validators, register_validators
from src.validators.utils import load_deposit_data, load_keystores

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=LOG_LEVEL,
)
logging.getLogger('backoff').addHandler(logging.StreamHandler())

logger = logging.getLogger(__name__)


def log_start() -> None:
    build = get_build_version()
    start_str = 'Starting operator service'

    if build:
        logger.info('%s, version %s, build %s', start_str, src.__version__, build)
    else:
        logger.info('%s, version %s', start_str, src.__version__)


async def main() -> None:
    log_start()

    await startup_checks()

    validators_db_setup()

    # load genesis validators for some networks
    await load_genesis_validators()

    # load keystores
    keystores = load_keystores()
    if not keystores:
        return

    # load deposit data
    deposit_data = await load_deposit_data()

    # start operator tasks

    # periodically scan network validator updates
    network_validators_processor = NetworkValidatorsProcessor()
    network_validators_scanner = EventScanner(network_validators_processor)

    logger.info('Syncing network validator events...')
    chain_state = await get_chain_finalized_head()
    to_block = chain_state.execution_block
    await network_validators_scanner.process_new_events(to_block)

    logger.info('Started operator service')
    interrupt_handler = InterruptHandler()
    while not interrupt_handler.exit:
        start_time = time.time()
        try:
            chain_state = await get_chain_finalized_head()
            to_block = chain_state.execution_block
            # process new network validators
            await network_validators_scanner.process_new_events(to_block)
            # check and register new validators
            await register_validators(keystores, deposit_data)

            # process outdated exit signatures
            await update_exit_signatures(keystores)
        except Exception as exc:
            log_verbose(exc)

        block_processing_time = time.time() - start_time
        sleep_time = max(int(NETWORK_CONFIG.SECONDS_PER_BLOCK) - int(block_processing_time), 0)
        await asyncio.sleep(sleep_time)


if __name__ == '__main__':
    # Pyinstaller hacks
    freeze_support()
    # Use certificate from certifi only if cafile could not find by ssl.
    if ssl.get_default_verify_paths().cafile is None and hasattr(sys, '_MEIPASS'):
        # pylint: disable-next=protected-access
        os.environ['SSL_CERT_FILE'] = os.path.join(sys._MEIPASS, 'certifi', 'cacert.pem')

    if SENTRY_DSN:
        import sentry_sdk
        from sentry_sdk.integrations.logging import ignore_logger

        sentry_sdk.init(SENTRY_DSN, traces_sample_rate=0.1)
        sentry_sdk.set_tag('network', NETWORK)
        sentry_sdk.set_tag('operator', operator_account.address)
        ignore_logger('backoff')

    try:
        asyncio.run(main())
    except Exception as e:
        log_verbose(e)
