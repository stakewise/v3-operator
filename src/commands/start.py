import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress

from src.commands.start_base import start_base
from src.common.logging import LOG_LEVELS
from src.common.utils import log_verbose
from src.common.validators import validate_eth_addresses
from src.common.vault_config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import (
    DEFAULT_HASHI_VAULT_PARALLELISM,
    DEFAULT_MAX_FEE_PER_GAS_GWEI,
    DEFAULT_METRICS_HOST,
    DEFAULT_METRICS_PORT,
    DEFAULT_METRICS_PREFIX,
    LOG_FORMATS,
    LOG_PLAIN,
    settings,
)

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
    '--metrics-prefix',
    type=str,
    help=f'The prometheus metrics prefix. Default is {DEFAULT_METRICS_PREFIX}.',
    envvar='METRICS_PREFIX',
    default=DEFAULT_METRICS_PREFIX,
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
    '--vaults',
    type=ChecksumAddress,
    callback=validate_eth_addresses,
    envvar='VAULT',
    prompt='Enter the vault address',
    help='Address of the vault to register validators for.',
)
@click.option(
    '--remote-signer-url',
    type=str,
    envvar='REMOTE_SIGNER_URL',
    help='The base URL of the remote signer, e.g. http://signer:9000',
)
@click.option(
    '--hashi-vault-url',
    envvar='HASHI_VAULT_URL',
    help='The base URL of the vault service, e.g. http://vault:8200.',
)
@click.option(
    '--hashi-vault-token',
    envvar='HASHI_VAULT_TOKEN',
    help='Authentication token for accessing Hashi vault.',
)
@click.option(
    '--hashi-vault-key-path',
    envvar='HASHI_VAULT_KEY_PATH',
    multiple=True,
    help='Key path(s) in the K/V secret engine where validator signing keys are stored.',
)
@click.option(
    '--hashi-vault-key-prefix',
    envvar='HASHI_VAULT_KEY_PREFIX',
    multiple=True,
    help='Key prefix(es) in the K/V secret engine under which validator signing keys are stored.',
)
@click.option(
    '--hashi-vault-parallelism',
    envvar='HASHI_VAULT_PARALLELISM',
    help='How much requests to K/V secrets engine to do in parallel.',
    default=DEFAULT_HASHI_VAULT_PARALLELISM,
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
    '--pool-size',
    help='Number of processes in a pool.',
    envvar='POOL_SIZE',
    type=int,
)
@click.option(
    '--min-validators-registration',
    type=int,
    envvar='MIN_VALIDATORS_REGISTRATION',
    help='Minimum number of validators required to start registration.',
    default=1,
)
@click.command(help='Start operator service')
# pylint: disable-next=too-many-arguments,too-many-locals
def start(
    vaults: list[ChecksumAddress],
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
    keystores_dir: str | None,
    keystores_password_file: str | None,
    remote_signer_url: str | None,
    hashi_vault_key_path: list[str] | None,
    hashi_vault_key_prefix: list[str] | None,
    hashi_vault_token: str | None,
    hashi_vault_url: str | None,
    hashi_vault_parallelism: int,
    hot_wallet_file: str | None,
    hot_wallet_password_file: str | None,
    max_fee_per_gas_gwei: int,
    database_dir: str | None,
    pool_size: int | None,
    min_validators_registration: int,
) -> None:
    vault_config = OperatorConfig(Path(data_dir))
    if network is None:
        vault_config.load()
        network = vault_config.network

    settings.set(
        vaults=vaults,
        config_dir=vault_config.config_dir,
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
        keystores_dir=keystores_dir,
        keystores_password_file=keystores_password_file,
        remote_signer_url=remote_signer_url,
        hashi_vault_token=hashi_vault_token,
        hashi_vault_key_paths=hashi_vault_key_path,
        hashi_vault_key_prefixes=hashi_vault_key_prefix,
        hashi_vault_parallelism=hashi_vault_parallelism,
        hashi_vault_url=hashi_vault_url,
        hot_wallet_file=hot_wallet_file,
        hot_wallet_password_file=hot_wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        database_dir=database_dir,
        log_level=log_level,
        log_format=log_format,
        pool_size=pool_size,
        min_validators_registration=min_validators_registration,
    )

    try:
        asyncio.run(start_base())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)
