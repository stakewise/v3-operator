import multiprocessing
import os
import ssl
import sys

import click

import src
from src.common.accounts import operator_account
from src.common.metrics import metrics_server
from src.config.settings import (
    HARVEST_VAULT,
    LOG_LEVEL,
    NETWORK,
    NETWORK_CONFIG,
    SENTRY_DSN,
)
from src.exits.tasks import update_exit_signatures
from src.harvest.tasks import harvest_vault
from src.startup_check import startup_checks
from src.utils import get_build_version, log_verbose
from src.validators.consensus import get_chain_finalized_head
from src.validators.database import setup as validators_db_setup
from src.validators.execution import (
    NetworkValidatorsProcessor,
    update_unused_validator_keys_metric,
)
from src.validators.tasks import load_genesis_validators, register_validators
from src.validators.utils import load_deposit_data, load_keystores

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=LOG_LEVEL,
)
logging.getLogger('backoff').addHandler(logging.StreamHandler())

logger = logging.getLogger(__name__)


@click.group()
def cli() -> None:
    pass


async def main() -> None:
    log_start()

    await startup_checks()

    validators_db_setup()

    # load network validators from ipfs dump
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

    await metrics_server()

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
            await update_unused_validator_keys_metric(keystores, deposit_data)
            await register_validators(keystores, deposit_data)
            # process outdated exit signatures
            await update_exit_signatures(keystores)

            # submit harvest vault transaction
            if HARVEST_VAULT:
                await harvest_vault()

        except Exception as exc:
            log_verbose(exc)

        block_processing_time = time.time() - start_time
        sleep_time = max(int(NETWORK_CONFIG.SECONDS_PER_BLOCK) - int(block_processing_time), 0)
        await asyncio.sleep(sleep_time)


if __name__ == '__main__':
    # Pyinstaller hacks
    multiprocessing.set_start_method('spawn')
    multiprocessing.freeze_support()
    # Use certificate from certifi only if cafile could not find by ssl.
    if ssl.get_default_verify_paths().cafile is None and hasattr(sys, '_MEIPASS'):
        # pylint: disable-next=protected-access
        os.environ['SSL_CERT_FILE'] = os.path.join(sys._MEIPASS, 'certifi', 'cacert.pem')

    cli()
