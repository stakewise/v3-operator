import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from web3.types import Gwei

from src.commands.start_base import start_base
from src.common.logging import LOG_LEVELS
from src.common.migrate import migrate_to_multivault
from src.common.typings import ValidatorType
from src.common.utils import log_verbose
from src.common.validators import (
    validate_eth_addresses,
    validate_min_deposit_amount_gwei,
)
from src.config.config import OperatorConfig, OperatorConfigException
from src.config.networks import AVAILABLE_NETWORKS, GNOSIS, MAINNET, NETWORKS
from src.config.settings import (
    DEFAULT_HASHI_VAULT_PARALLELISM,
    DEFAULT_METRICS_HOST,
    DEFAULT_METRICS_PORT,
    DEFAULT_METRICS_PREFIX,
    DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
    DEFAULT_MIN_VALIDATORS_REGISTRATION,
    LOG_FORMATS,
    LOG_PLAIN,
    settings,
)

logger = logging.getLogger(__name__)


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
    envvar='SPLIT_REWARDS',
    help='Claim fee rewards periodically on behalf of the shareholders. Default is false.',
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
    '--graph-endpoint',
    type=str,
    envvar='GRAPH_ENDPOINT',
    help='API endpoint for graph node.',
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
    default=DEFAULT_MIN_VALIDATORS_REGISTRATION,
)
@click.option(
    '--min-deposit-amount-gwei',
    type=int,
    envvar='MIN_DEPOSIT_AMOUNT_GWEI',
    help='Minimum amount in gwei to deposit into validator.',
    default=DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
    callback=validate_min_deposit_amount_gwei,
)
@click.option(
    '--no-confirm',
    is_flag=True,
    default=False,
    help='Skips confirmation messages when provided.',
)
@click.command(help='Start operator service')
# pylint: disable-next=too-many-arguments,too-many-locals
def start(
    vaults: list[ChecksumAddress],
    consensus_endpoints: str,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    harvest_vault: bool,
    split_rewards: bool,
    verbose: bool,
    enable_metrics: bool,
    metrics_host: str,
    metrics_port: int,
    metrics_prefix: str,
    validator_type: ValidatorType,
    data_dir: str,
    log_level: str,
    log_format: str,
    network: str | None,
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
    max_fee_per_gas_gwei: int | None,
    database_dir: str | None,
    pool_size: int | None,
    min_validators_registration: int,
    min_deposit_amount_gwei: int,
    no_confirm: bool,
) -> None:

    # migrate
    try:
        operator_config = OperatorConfig(Path(data_dir))
        operator_config.load(network=network)
    except OperatorConfigException as e:
        if not e.can_be_migrated:
            raise click.ClickException(str(e))

        # trying to migrate from single vault setup to multivault
        vault = vaults[0].lower()
        root_dir = Path(data_dir)
        vault_dir = root_dir / vault
        if Path(vault_dir).exists() and not (root_dir / 'config.json').exists():
            if not no_confirm:
                click.confirm(
                    f'There is vault directory {vault_dir} already. '
                    'Do you want to migrate to multivault setup?',
                    default=True,
                )
            migrate_to_multivault(
                vault_dir=vault_dir,
                root_dir=root_dir,
            )
        operator_config = OperatorConfig(Path(data_dir))
        operator_config.load()

    settings.set(
        vaults=vaults,
        data_dir=operator_config.data_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_endpoint=graph_endpoint,
        harvest_vault=harvest_vault,
        split_rewards=split_rewards,
        verbose=verbose,
        enable_metrics=enable_metrics,
        metrics_host=metrics_host,
        metrics_port=metrics_port,
        metrics_prefix=metrics_prefix,
        network=operator_config.network,
        validator_type=validator_type,
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
        min_deposit_amount_gwei=Gwei(min_deposit_amount_gwei),
    )

    try:
        asyncio.run(start_base())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)
