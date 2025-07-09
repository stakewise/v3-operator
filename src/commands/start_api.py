import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from web3.types import Gwei

from src.commands.start_base import start_base
from src.common.logging import LOG_LEVELS
from src.common.typings import ValidatorType
from src.common.utils import log_verbose
from src.common.validators import validate_eth_addresses
from src.config.config import OperatorConfig, OperatorConfigException
from src.config.networks import AVAILABLE_NETWORKS, GNOSIS, MAINNET, NETWORKS
from src.config.settings import (
    DEFAULT_METRICS_HOST,
    DEFAULT_METRICS_PORT,
    DEFAULT_METRICS_PREFIX,
    DEFAULT_MIN_DEPOSIT_AMOUNT,
    LOG_FORMATS,
    LOG_PLAIN,
    settings,
)
from src.validators.typings import RelayerTypes, ValidatorsRegistrationMode

logger = logging.getLogger(__name__)


# Special value used to dynamically determine option value
AUTO = 'AUTO'


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the keystores and config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--database-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='DATABASE_DIR',
    help='The directory where the database will be created or read from. '
    'Default is ~/.stakewise/.',
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
    '--validator-type',
    help=f'Type of registered validators: {ValidatorType.V1.value} or {ValidatorType.V2.value}.',
    envvar='VALIDATOR_TYPE',
    default=ValidatorType.V2,
    type=click.Choice(
        ValidatorType,
        case_sensitive=False,
    ),
)
@click.option(
    '--min-deposit-amount-gwei',
    type=int,
    envvar='MIN_DEPOSIT_AMOUNT_GWEI',
    help='Minimum amount in gwei to deposit into validator.',
    default=DEFAULT_MIN_DEPOSIT_AMOUNT,
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
    '--split-rewards',
    is_flag=True,
    envvar='split_rewards',
    help='Withdraw and claim shareholders rewards in reward splitter '
    'on behalf of shareholders. Default is false.',
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
    '--graph-api-url',
    type=str,
    envvar='GRAPH_API_URL',
    prompt='Enter API endpoint for graph node',
    help='API endpoint for graph nodes.',
)
@click.option(
    '--vaults',
    type=ChecksumAddress,
    callback=validate_eth_addresses,
    envvar='VAULTS',
    prompt='Enter comma separated list of your vault addresses',
    help='Addresses of the vaults to register validators for.',
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
    '--relayer-type',
    type=click.Choice(
        [RelayerTypes.DEFAULT, RelayerTypes.DVT],
        case_sensitive=False,
    ),
    default=RelayerTypes.DEFAULT,
    help='Relayer type.',
    envvar='RELAYER_TYPE',
)
@click.option(
    '--relayer-endpoint',
    type=str,
    help='Relayer endpoint.',
    prompt='Enter the relayer endpoint',
    envvar='RELAYER_ENDPOINT',
    default=AUTO,
)
@click.command(help='Start operator service')
# pylint: disable-next=too-many-arguments,too-many-locals
def start_api(
    vaults: list[ChecksumAddress],
    consensus_endpoints: str,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_api_url: str,
    harvest_vault: bool,
    split_rewards: bool,
    verbose: bool,
    enable_metrics: bool,
    metrics_host: str,
    metrics_port: int,
    metrics_prefix: str,
    validator_type: ValidatorType,
    min_deposit_amount_gwei: int,
    data_dir: str,
    log_level: str,
    log_format: str,
    network: str | None,
    hot_wallet_file: str | None,
    hot_wallet_password_file: str | None,
    max_fee_per_gas_gwei: int | None,
    database_dir: str | None,
    relayer_type: str,
    relayer_endpoint: str,
) -> None:
    operator_config = OperatorConfig(Path(data_dir))
    if network is None:
        try:
            operator_config.load(network=network)
        except OperatorConfigException as e:
            raise click.ClickException(str(e))
        network = operator_config.network

    if relayer_endpoint == AUTO and relayer_type == RelayerTypes.DVT:
        network_config = NETWORKS[network]
        relayer_endpoint = network_config.DEFAULT_DVT_RELAYER_ENDPOINT

    if relayer_endpoint == AUTO and relayer_type == RelayerTypes.DEFAULT:
        raise click.ClickException('Relayer endpoint must be specified for default relayer type')

    validators_registration_mode = ValidatorsRegistrationMode.API

    settings.set(
        vaults=vaults,
        data_dir=operator_config.data_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_api_url=graph_api_url,
        harvest_vault=harvest_vault,
        split_rewards=split_rewards,
        verbose=verbose,
        enable_metrics=enable_metrics,
        metrics_host=metrics_host,
        metrics_port=metrics_port,
        metrics_prefix=metrics_prefix,
        validator_type=validator_type,
        network=network,
        hot_wallet_file=hot_wallet_file,
        hot_wallet_password_file=hot_wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        database_dir=database_dir,
        log_level=log_level,
        log_format=log_format,
        relayer_type=relayer_type,
        relayer_endpoint=relayer_endpoint,
        validators_registration_mode=validators_registration_mode,
        min_deposit_amount=Gwei(min_deposit_amount_gwei),
    )

    try:
        asyncio.run(start_base())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)
