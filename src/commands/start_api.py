import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress

import src.validators.api.endpoints  # noqa  # pylint:disable=unused-import
from src.commands.start_base import start_base
from src.common.logging import LOG_LEVELS
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import (
    DEFAULT_API_HOST,
    DEFAULT_API_PORT,
    DEFAULT_MAX_FEE_PER_GAS_GWEI,
    DEFAULT_METRICS_HOST,
    DEFAULT_METRICS_PORT,
    DEFAULT_METRICS_PREFIX,
    LOG_FORMATS,
    LOG_PLAIN,
    settings,
)
from src.validators.typings import ValidatorsRegistrationMode

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
    help=f'Maximum fee per gas for transactions. '
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
    '--enable-metrics',
    is_flag=True,
    envvar='ENABLE_METRICS',
    help='Whether to enable metrics server. Disabled by default.',
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
    '--metrics-prefix',
    type=str,
    help=f'The prometheus metrics prefix. Default is {DEFAULT_METRICS_PREFIX}.',
    envvar='METRICS_PREFIX',
    default=DEFAULT_METRICS_PREFIX,
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
    '--execution-jwt-secret',
    type=str,
    envvar='EXECUTION_JWT_SECRET',
    help='JWT secret key used for signing and verifying JSON Web Tokens'
    'when connecting to execution nodes.',
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
    '--api-host',
    type=str,
    help=f'API host. Default is {DEFAULT_API_HOST}.',
    envvar='API_HOST',
    default=DEFAULT_API_HOST,
)
@click.option(
    '--api-port',
    type=int,
    help=f'API port. Default is {DEFAULT_API_PORT}.',
    envvar='API_PORT',
    default=DEFAULT_API_PORT,
)
@click.command(help='Start operator service')
# pylint: disable-next=too-many-arguments,too-many-locals
def start_api(
    vault: ChecksumAddress,
    consensus_endpoints: str,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    harvest_vault: bool,
    verbose: bool,
    enable_metrics: bool,
    metrics_host: str,
    metrics_port: int,
    metrics_prefix: str,
    data_dir: str,
    log_level: str,
    log_format: str,
    network: str | None,
    deposit_data_file: str | None,
    hot_wallet_file: str | None,
    hot_wallet_password_file: str | None,
    max_fee_per_gas_gwei: int,
    database_dir: str | None,
    api_host: str,
    api_port: int,
) -> None:
    vault_config = VaultConfig(vault, Path(data_dir))
    if network is None:
        vault_config.load()
        network = vault_config.network

    validators_registration_mode = ValidatorsRegistrationMode.API

    settings.set(
        vault=vault,
        vault_dir=vault_config.vault_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        harvest_vault=harvest_vault,
        verbose=verbose,
        enable_metrics=enable_metrics,
        metrics_host=metrics_host,
        metrics_port=metrics_port,
        metrics_prefix=metrics_prefix,
        network=network,
        deposit_data_file=deposit_data_file,
        hot_wallet_file=hot_wallet_file,
        hot_wallet_password_file=hot_wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        database_dir=database_dir,
        log_level=log_level,
        log_format=log_format,
        api_host=api_host,
        api_port=api_port,
        validators_registration_mode=validators_registration_mode,
    )

    try:
        asyncio.run(start_base())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)
