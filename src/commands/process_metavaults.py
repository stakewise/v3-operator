import asyncio
import logging
import sys
from pathlib import Path

import click
from decouple import config as decouple_config
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from sw_utils import InterruptHandler
from web3.types import Gwei

from src.commands.start.base import log_start, setup_sentry
from src.common.clients import setup_clients
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.common.validators import validate_eth_addresses
from src.config.networks import AVAILABLE_NETWORKS, GNOSIS, MAINNET, NETWORKS
from src.config.settings import (
    DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
    LOG_FORMATS,
    LOG_PLAIN,
    settings,
)
from src.meta_vault.tasks import ProcessMetaVaultTask

logger = logging.getLogger(__name__)


@click.option(
    '--vaults',
    callback=validate_eth_addresses,
    envvar='VAULTS',
    prompt='Enter the comma separated list of your meta vault addresses',
    help='Addresses of the meta vaults to process.',
)
@click.option(
    '--max-fee-per-gas-gwei',
    type=int,
    envvar='MAX_FEE_PER_GAS_GWEI',
    help=f'Maximum fee per gas for transactions. '
    f'Default is {NETWORKS[MAINNET].MAX_FEE_PER_GAS_GWEI} Gwei for Ethereum, '
    f'{NETWORKS[GNOSIS].MAX_FEE_PER_GAS_GWEI} Gwei for Gnosis.',
)
@click.option(
    '--wallet-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_PASSWORD_FILE',
    help='Absolute path to the wallet password file. '
    'Must be used if WALLET_PRIVATE_KEY environment variable is not set.',
)
@click.option(
    '--wallet-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_FILE',
    help='Absolute path to the wallet. '
    'Must be used if WALLET_PRIVATE_KEY environment variable is not set.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--min-deposit-amount-gwei',
    type=int,
    envvar='MIN_DEPOSIT_AMOUNT_GWEI',
    help=f'Minimum amount in gwei that must accumulate in the vault '
    f'to trigger deposits to the sub-vaults.'
    f' The default is {DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI}',
    default=DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter the comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '--graph-endpoint',
    type=str,
    envvar='GRAPH_ENDPOINT',
    help='API endpoint for graph node.',
)
@click.option(
    '--log-format',
    type=click.Choice(
        LOG_FORMATS,
        case_sensitive=False,
    ),
    default=LOG_PLAIN,
    envvar='LOG_FORMAT',
    help='The log record format. Can be "plain" or "json".',
)
@click.option(
    '--log-level',
    type=click.Choice(
        LOG_LEVELS,
        case_sensitive=False,
    ),
    default='INFO',
    envvar='LOG_LEVEL',
    help='The log level.',
)
@click.option(
    '--network',
    help='The network of the meta vaults.',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Updates states and processes deposits and exits for one or more meta vaults.')
# pylint: disable-next=too-many-arguments,too-many-locals
def process_metavaults(
    vaults: str,
    execution_endpoints: str,
    graph_endpoint: str,
    network: str,
    verbose: bool,
    log_level: str,
    log_format: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
    max_fee_per_gas_gwei: int | None,
    min_deposit_amount_gwei: int,
) -> None:
    # Validate wallet configuration
    has_private_key = decouple_config('WALLET_PRIVATE_KEY', default=None) is not None
    has_wallet_files = wallet_file is not None and wallet_password_file is not None

    if not has_private_key and not has_wallet_files:
        raise click.ClickException(
            'Either WALLET_PRIVATE_KEY environment variable must be set, '
            'or both --wallet-file and --wallet-password-file options must be provided.'
        )

    if has_private_key and has_wallet_files:
        logger.warning(
            'Both WALLET_PRIVATE_KEY and wallet files are provided. '
            'WALLET_PRIVATE_KEY will take precedence.'
        )

    vault_addresses = [to_checksum_address(address) for address in vaults.split(',')]
    settings.set(
        # mock vault and vault_dir
        vault=vault_addresses[0],
        vault_dir=Path.home() / '.stakewise',
        execution_endpoints=execution_endpoints,
        graph_endpoint=graph_endpoint,
        verbose=verbose,
        network=network,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        log_level=log_level,
        log_format=log_format,
        meta_vault_min_deposit_amount_gwei=Gwei(min_deposit_amount_gwei),
    )
    try:
        asyncio.run(main(vault_addresses))
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(vaults: list[ChecksumAddress]) -> None:
    setup_logging()
    setup_sentry()
    await setup_clients()
    log_start()

    logger.info('Started meta vault processing')
    with InterruptHandler() as interrupt_handler:
        await ProcessMetaVaultTask(vaults).run(interrupt_handler)
