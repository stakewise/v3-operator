from pathlib import Path
from typing import Callable

import click
from click.decorators import FC

from src.common.logging import LOG_LEVELS
from src.common.typings import ValidatorType
from src.common.validators import (
    validate_eth_addresses,
    validate_min_deposit_amount_gwei,
)
from src.config.networks import AVAILABLE_NETWORKS, GNOSIS, MAINNET, NETWORKS
from src.config.settings import (
    DEFAULT_METRICS_HOST,
    DEFAULT_METRICS_PORT,
    DEFAULT_METRICS_PREFIX,
    DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
    DEFAULT_MIN_VALIDATORS_REGISTRATION,
    LOG_FORMATS,
    LOG_PLAIN,
)

start_common_options = [
    click.option(
        '--data-dir',
        default=str(Path.home() / '.stakewise'),
        envvar='DATA_DIR',
        help='Path where the keystores and config data will be placed. Default is ~/.stakewise.',
        type=click.Path(exists=True, file_okay=False, dir_okay=True),
    ),
    click.option(
        '--database-dir',
        type=click.Path(exists=True, file_okay=False, dir_okay=True),
        envvar='DATABASE_DIR',
        help='The directory where the database will be created or read from. '
        'Default is ~/.stakewise/.',
    ),
    click.option(
        '--max-fee-per-gas-gwei',
        type=int,
        envvar='MAX_FEE_PER_GAS_GWEI',
        help=f'Maximum fee per gas for transactions. '
        f'Default is {NETWORKS[MAINNET].MAX_FEE_PER_GAS_GWEI} Gwei for Ethereum, '
        f'{NETWORKS[GNOSIS].MAX_FEE_PER_GAS_GWEI} Gwei for Gnosis.',
    ),
    click.option(
        '--wallet-password-file',
        type=click.Path(exists=True, file_okay=True, dir_okay=False),
        envvar='WALLET_PASSWORD_FILE',
        help='Absolute path to the wallet password file. '
        'Default is the file generated with "create-wallet" command.',
    ),
    click.option(
        '--wallet-file',
        type=click.Path(exists=True, file_okay=True, dir_okay=False),
        envvar='WALLET_FILE',
        help='Absolute path to the wallet. '
        'Default is the file generated with "create-wallet" command.',
    ),
    click.option(
        '--network',
        type=click.Choice(
            AVAILABLE_NETWORKS,
            case_sensitive=False,
        ),
        envvar='NETWORK',
        help='The network of the vault. Default is the network specified at "init" command.',
    ),
    click.option(
        '--enable-metrics',
        is_flag=True,
        envvar='ENABLE_METRICS',
        help='Whether to enable metrics server. Disabled by default.',
    ),
    click.option(
        '--metrics-host',
        type=str,
        help=f'The prometheus metrics host. Default is {DEFAULT_METRICS_HOST}.',
        envvar='METRICS_HOST',
        default=DEFAULT_METRICS_HOST,
    ),
    click.option(
        '--metrics-prefix',
        type=str,
        help=f'The prometheus metrics prefix. Default is {DEFAULT_METRICS_PREFIX}.',
        envvar='METRICS_PREFIX',
        default=DEFAULT_METRICS_PREFIX,
    ),
    click.option(
        '--metrics-port',
        type=int,
        help=f'The prometheus metrics port. Default is {DEFAULT_METRICS_PORT}.',
        envvar='METRICS_PORT',
        default=DEFAULT_METRICS_PORT,
    ),
    click.option(
        '--validator-type',
        help='Type of registered validators: '
        f'{ValidatorType.V1.value} or {ValidatorType.V2.value}.',
        envvar='VALIDATOR_TYPE',
        default=ValidatorType.V2,
        type=click.Choice(
            ValidatorType,
            case_sensitive=False,
        ),
    ),
    click.option(
        '-v',
        '--verbose',
        help='Enable debug mode. Default is false.',
        envvar='VERBOSE',
        is_flag=True,
    ),
    click.option(
        '--harvest-vault',
        is_flag=True,
        envvar='HARVEST_VAULT',
        help='Whether to submit vault harvest transactions. Default is false.',
    ),
    click.option(
        '--split-rewards',
        is_flag=True,
        envvar='SPLIT_REWARDS',
        help='Claim fee rewards periodically on behalf of the shareholders. Default is false.',
    ),
    click.option(
        '--disable-withdrawals',
        is_flag=True,
        envvar='DISABLE_WITHDRAWALS',
        help='Whether to disable submitting partial vault withdrawals.',
    ),
    click.option(
        '--execution-endpoints',
        type=str,
        envvar='EXECUTION_ENDPOINTS',
        prompt='Enter comma separated list of API endpoints for execution nodes',
        help='Comma separated list of API endpoints for execution nodes.',
    ),
    click.option(
        '--execution-jwt-secret',
        type=str,
        envvar='EXECUTION_JWT_SECRET',
        help='JWT secret key used for signing and verifying JSON Web Tokens'
        'when connecting to execution nodes.',
    ),
    click.option(
        '--consensus-endpoints',
        type=str,
        envvar='CONSENSUS_ENDPOINTS',
        prompt='Enter comma separated list of API endpoints for consensus nodes',
        help='Comma separated list of API endpoints for consensus nodes.',
    ),
    click.option(
        '--graph-endpoint',
        type=str,
        envvar='GRAPH_ENDPOINT',
        help='API endpoint for graph node.',
    ),
    click.option(
        '--vaults',
        '--vault',
        callback=validate_eth_addresses,
        envvar='VAULTS',
        prompt='Enter comma separated list of your vault addresses',
        help='Addresses of the vaults to register validators for.',
    ),
    click.option(
        '--log-format',
        type=click.Choice(
            LOG_FORMATS,
            case_sensitive=False,
        ),
        default=LOG_PLAIN,
        envvar='LOG_FORMAT',
        help='The log record format. Can be "plain" or "json".',
    ),
    click.option(
        '--log-level',
        type=click.Choice(
            LOG_LEVELS,
            case_sensitive=False,
        ),
        default='INFO',
        envvar='LOG_LEVEL',
        help='The log level.',
    ),
    click.option(
        '--pool-size',
        help='Number of processes in a pool.',
        envvar='POOL_SIZE',
        type=int,
    ),
    click.option(
        '--min-validators-registration',
        type=int,
        envvar='MIN_VALIDATORS_REGISTRATION',
        help='Minimum number of validators required to start registration.',
        default=DEFAULT_MIN_VALIDATORS_REGISTRATION,
    ),
    click.option(
        '--min-deposit-amount-gwei',
        type=int,
        envvar='MIN_DEPOSIT_AMOUNT_GWEI',
        help='Minimum amount in gwei to deposit into validator.',
        default=DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
        callback=validate_min_deposit_amount_gwei,
    ),
    click.option(
        '--no-confirm',
        is_flag=True,
        default=False,
        help='Skips confirmation messages when provided.',
    ),
]


def add_common_options(options: list[Callable[[FC], FC]]) -> Callable:
    def _add_common_options(func: FC) -> Callable:
        for option in reversed(options):
            func = option(func)
        return func

    return _add_common_options
