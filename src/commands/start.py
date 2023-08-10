import asyncio
import logging
import time
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from sw_utils import EventScanner, InterruptHandler
from sw_utils.typings import ChainHead

import src
from src.common.clients import consensus_client, execution_client
from src.common.execution import check_hot_wallet_balance
from src.common.metrics import metrics, metrics_server
from src.common.startup_check import startup_checks
from src.common.utils import get_build_version, log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import (
    AVAILABLE_NETWORKS,
    DEFAULT_MAX_FEE_PER_GAS_GWEI,
    DEFAULT_METRICS_HOST,
    DEFAULT_METRICS_PORT,
    settings,
)
from src.exits.tasks import update_exit_signatures_periodically
from src.harvest.tasks import harvest_vault as harvest_vault_task
from src.validators.database import NetworkValidatorCrud
from src.validators.execution import (
    NetworkValidatorsProcessor,
    update_unused_validator_keys_metric,
)
from src.validators.tasks import load_genesis_validators, register_validators
from src.validators.utils import load_deposit_data, load_keystores

logger = logging.getLogger(__name__)


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--database-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='DATABASE_DIR',
    help='The directory where the database will be created or read from. '
    'Default is ~/.stakewise/<vault>.',
)
@click.option(
    '--max-fee-per-gas-gwei',
    type=int,
    envvar='MAX_FEE_PER_GAS_GWEI',
    help=f'Maximum fee per gas limit for transactions. '
    f'Default is {DEFAULT_MAX_FEE_PER_GAS_GWEI} Gwei.',
    default=DEFAULT_MAX_FEE_PER_GAS_GWEI,
)
@click.option(
    '--hot-wallet-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='HOT_WALLET_PASSWORD_FILE',
    help='Absolute path to the hot wallet password file. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--hot-wallet-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='HOT_WALLET_FILE',
    help='Absolute path to the hot wallet. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--keystores-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='KEYSTORES_PASSWORD_FILE',
    help='Absolute path to the password file for decrypting keystores. '
    'Default is the file generated with "create-keys" command.',
)
@click.option(
    '--keystores-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='KEYSTORES_DIR',
    help='Absolute path to the directory with all the encrypted keystores. '
    'Default is the directory generated with "create-keys" command.',
)
@click.option(
    '--deposit-data-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='DEPOSIT_DATA_FILE',
    help='Path to the deposit_data.json file. '
    'Default is the file generated with "create-keys" command.',
)
@click.option(
    '--network',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
    envvar='NETWORK',
    help='The network of the vault. Default is the network specified at "init" command.',
)
@click.option(
    '--metrics-host',
    type=str,
    help=f'The prometheus metrics host. Default is {DEFAULT_METRICS_HOST}.',
    envvar='METRICS_HOST',
    default=DEFAULT_METRICS_HOST,
)
@click.option(
    '--metrics-port',
    type=int,
    help=f'The prometheus metrics port. Default is {DEFAULT_METRICS_PORT}.',
    envvar='METRICS_PORT',
    default=DEFAULT_METRICS_PORT,
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--harvest-vault',
    is_flag=True,
    envvar='HARVEST_VAULT',
    help='Whether to submit vault harvest transactions. Default is false.',
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '--consensus-endpoints',
    type=str,
    envvar='CONSENSUS_ENDPOINTS',
    prompt='Enter comma separated list of API endpoints for consensus nodes',
    help='Comma separated list of API endpoints for consensus nodes.',
)
@click.option(
    '--vault',
    type=ChecksumAddress,
    callback=validate_eth_address,
    envvar='VAULT',
    prompt='Enter the vault address',
    help='Address of the vault to register validators for.',
)
@click.command(help='Start operator service')
# pylint: disable-next=too-many-arguments,too-many-locals
def start(
    vault: ChecksumAddress,
    consensus_endpoints: str,
    execution_endpoints: str,
    harvest_vault: bool,
    verbose: bool,
    metrics_host: str,
    metrics_port: int,
    data_dir: str,
    network: str | None,
    deposit_data_file: str | None,
    keystores_dir: str | None,
    keystores_password_file: str | None,
    hot_wallet_file: str | None,
    hot_wallet_password_file: str | None,
    max_fee_per_gas_gwei: int,
    database_dir: str | None,
) -> None:
    vault_config = VaultConfig(vault, Path(data_dir))
    if network is None:
        vault_config.load()
        network = vault_config.network

    settings.set(
        vault=vault,
        vault_dir=vault_config.vault_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        harvest_vault=harvest_vault,
        verbose=verbose,
        metrics_host=metrics_host,
        metrics_port=metrics_port,
        network=network,
        deposit_data_file=deposit_data_file,
        keystores_dir=keystores_dir,
        keystores_password_file=keystores_password_file,
        hot_wallet_file=hot_wallet_file,
        hot_wallet_password_file=hot_wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        database_dir=database_dir,
    )

    try:
        asyncio.run(main())
    except Exception as e:
        log_verbose(e)


async def main() -> None:
    setup_logging()
    setup_sentry()
    log_start()

    await startup_checks()

    NetworkValidatorCrud().setup()

    # load network validators from ipfs dump
    await load_genesis_validators()

    # load keystores
    keystores = load_keystores()
    if not keystores:
        return

    # load deposit data
    deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
    logger.info('Loaded deposit data file %s', settings.deposit_data_file)
    # start operator tasks

    # periodically scan network validator updates
    network_validators_processor = NetworkValidatorsProcessor()
    network_validators_scanner = EventScanner(network_validators_processor)

    logger.info('Syncing network validator events...')
    chain_state = await get_chain_finalized_head()

    to_block = chain_state.execution_block
    await network_validators_scanner.process_new_events(to_block)
    await metrics_server()

    # process outdated exit signatures
    asyncio.create_task(update_exit_signatures_periodically(keystores))

    logger.info('Started operator service')
    with InterruptHandler() as interrupt_handler:
        while not interrupt_handler.exit:
            start_time = time.time()
            try:
                chain_state = await get_chain_finalized_head()
                metrics.slot_number.set(chain_state.consensus_block)

                to_block = chain_state.execution_block
                # process new network validators
                await network_validators_scanner.process_new_events(to_block)
                # check and register new validators
                await update_unused_validator_keys_metric(keystores, deposit_data)
                await register_validators(keystores, deposit_data)

                # submit harvest vault transaction
                if settings.harvest_vault:
                    await harvest_vault_task()

                # check balance
                await check_hot_wallet_balance()

                # update metrics
                metrics.block_number.set(await execution_client.eth.get_block_number())

            except Exception as exc:
                log_verbose(exc)

            block_processing_time = time.time() - start_time
            sleep_time = max(
                float(settings.network_config.SECONDS_PER_BLOCK) - block_processing_time, 0
            )
            await asyncio.sleep(sleep_time)


def log_start() -> None:
    build = get_build_version()
    start_str = 'Starting operator service'

    if build:
        logger.info('%s, version %s, build %s', start_str, src.__version__, build)
    else:
        logger.info('%s, version %s', start_str, src.__version__)


def setup_sentry():
    if settings.sentry_dsn:
        # pylint: disable-next=import-outside-toplevel
        import sentry_sdk

        sentry_sdk.init(settings.sentry_dsn, traces_sample_rate=0.1)
        sentry_sdk.set_tag('network', settings.network)
        sentry_sdk.set_tag('vault', settings.vault)


def setup_logging():
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=settings.log_level,
    )


async def get_chain_finalized_head() -> ChainHead:
    return await consensus_client.get_chain_finalized_head(settings.network_config.SLOTS_PER_EPOCH)
