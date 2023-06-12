import asyncio
import logging
import time

import click
from sw_utils import EventScanner, InterruptHandler

import src
from src.common.accounts import OperatorAccount
from src.common.validators import validate_eth_address
from src.config.settings import AVAILABLE_NETWORKS, GOERLI, SettingsStore
from src.exits.tasks import update_exit_signatures
from src.harvest.tasks import harvest_vault
from src.startup_check import startup_checks
from src.utils import get_build_version, log_verbose
from src.validators.consensus import get_chain_finalized_head
from src.validators.database import setup as validators_db_setup
from src.validators.execution import NetworkValidatorsProcessor
from src.validators.tasks import load_genesis_validators, register_validators
from src.validators.utils import load_deposit_data, load_keystores

logger = logging.getLogger(__name__)


@click.option(
    '--network',
    default=GOERLI,
    help='The network of the Vault',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.option('--vault', type=str,
              help='Address of the Vault to register validators for', callback=validate_eth_address)
@click.option('--database-dir', type=str,
              help='The directory where the database will be created or read from')
@click.option('--execution-endpoint', type=str,
              help='API endpoint for the execution node')
@click.option('--consensus-endpoint', type=str,
              help='API endpoint for the consensus node')
@click.option('--max-fee-per-gas-gwei', type=int,
              help='Maximum fee per gas limit')
@click.option('--keystores-password-file', type=str,
              help='Absolute path to the password file for decrypting keystores')
@click.option('--keystores-password-dir', type=str,
              help='Absolute path to the password file for decrypting keystores')
@click.option('--keystores-path', type=str,
              help='Absolute path to the directory with all the encrypted keystores')
@click.option('--deposit-data-path', type=str,
              help='Path to the deposit_data.json file')
@click.option('--hot-wallet-private-key', type=str,
              help='Private key of the hot wallet with ETH for submitting transactions')
@click.option('--hot-wallet-keystore-path', type=str,
              help='Absolute path to the directory with all the encrypted keystores')
@click.option('--hot-wallet-keystore-password-path', type=str,
              help='Absolute path to the password file for decrypting keystores')
@click.option('--harvest-vault', type=bool,
              help='Periodically submit vault harvest transaction')
@click.option('-v', '--verbose', help='Enable debug mode', is_flag=True)
@click.command(help='Start operator service')
def worker(*args, **kwargs) -> None:
    # setup config
    SettingsStore(*args, **kwargs)
    try:
        asyncio.run(main())
    except Exception as e:
        log_verbose(e)


async def main() -> None:
    setup_logging()
    setup_sentry()
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

            # submit harvest vault transaction
            if SettingsStore().HARVEST_VAULT:
                await harvest_vault()

        except Exception as exc:
            log_verbose(exc)

        block_processing_time = time.time() - start_time
        sleep_time = max(
            int(SettingsStore().NETWORK_CONFIG.SECONDS_PER_BLOCK) - int(block_processing_time),
            0
        )
        await asyncio.sleep(sleep_time)


def log_start() -> None:
    build = get_build_version()
    start_str = 'Starting operator service'

    if build:
        logger.info('%s, version %s, build %s', start_str, src.__version__, build)
    else:
        logger.info('%s, version %s', start_str, src.__version__)


def setup_logging() -> None:
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=SettingsStore().LOG_LEVEL,
    )
    logging.getLogger('backoff').addHandler(logging.StreamHandler())


def setup_sentry():
    if SettingsStore().SENTRY_DSN:
        # pylint: disable-next=import-outside-toplevel
        import sentry_sdk

        # pylint: disable-next=import-outside-toplevel
        from sentry_sdk.integrations.logging import ignore_logger

        sentry_sdk.init(SettingsStore().SENTRY_DSN, traces_sample_rate=0.1)
        sentry_sdk.set_tag('network', SettingsStore().NETWORK)
        sentry_sdk.set_tag('operator', OperatorAccount().operator_account.address)
        ignore_logger('backoff')
