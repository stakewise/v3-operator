import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from sw_utils import InterruptHandler
from web3.types import Gwei

from src.common.clients import close_clients, setup_clients
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.protocol_config import update_oracles_cache
from src.common.typings import ValidatorType
from src.common.utils import log_verbose
from src.common.validators import (
    validate_eth_address,
    validate_max_validator_balance_gwei,
)
from src.config.networks import AVAILABLE_NETWORKS, MAINNET, NETWORKS
from src.config.settings import (
    DEFAULT_CONSENSUS_ENDPOINT,
    DEFAULT_EXECUTION_ENDPOINT,
    LOG_FORMATS,
    LOG_PLAIN,
    settings,
)
from src.node_manager.startup_check import startup_checks
from src.node_manager.tasks import NodeManagerTask, StateSyncTask
from src.validators.database import NetworkValidatorCrud
from src.validators.keystores.load import load_keystore

logger = logging.getLogger(__name__)


@click.option(
    '--keystores-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='KEYSTORES_PASSWORD_FILE',
    help='Absolute path to the password file for decrypting keystores.',
)
@click.option(
    '--keystores-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='KEYSTORES_DIR',
    help='Absolute path to the directory with all the encrypted keystores.',
)
@click.option(
    '--wallet-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_PASSWORD_FILE',
    help='Absolute path to the wallet password file.',
)
@click.option(
    '--wallet-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_FILE',
    help='Absolute path to the wallet.',
)
@click.option(
    '--max-validator-balance-gwei',
    type=int,
    envvar='MAX_VALIDATOR_BALANCE_GWEI',
    help=f'The maximum validator balance in Gwei. '
    f'Default is {NETWORKS[MAINNET].MAX_VALIDATOR_BALANCE_GWEI} Gwei',
    callback=validate_max_validator_balance_gwei,
)
@click.option(
    '--validator-type',
    help='Type of the validators to register:'
    f' {ValidatorType.V1.value} or {ValidatorType.V2.value}.',
    envvar='VALIDATOR_TYPE',
    default=ValidatorType.V2.value,
    type=click.Choice(
        [x.value for x in ValidatorType],
        case_sensitive=False,
    ),
    callback=lambda ctx, param, value: ValidatorType(value),
    show_default=True,
)
@click.option(
    '--max-fee-per-gas-gwei',
    type=int,
    envvar='MAX_FEE_PER_GAS_GWEI',
    help=f'Maximum fee per gas for transactions. '
    f'Default is {NETWORKS[MAINNET].MAX_FEE_PER_GAS_GWEI} Gwei',
)
@click.option(
    '--operator-address',
    callback=validate_eth_address,
    envvar='OPERATOR_ADDRESS',
    prompt='Enter your operator withdrawals (cold wallet) address',
    help='The operator withdrawals (cold wallet) address.',
)
@click.option(
    '--network',
    help='The network to run on.',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
    envvar='NETWORK',
    prompt='Enter the network',
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--log-format',
    type=click.Choice(LOG_FORMATS, case_sensitive=False),
    default=LOG_PLAIN,
    envvar='LOG_FORMAT',
    help='The log record format. Can be "plain" or "json".',
)
@click.option(
    '--log-level',
    type=click.Choice(LOG_LEVELS, case_sensitive=False),
    default='INFO',
    envvar='LOG_LEVEL',
    help='The log level.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    default=DEFAULT_EXECUTION_ENDPOINT,
    prompt='Enter the comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
    show_default=True,
)
@click.option(
    '--execution-jwt-secret',
    type=str,
    envvar='EXECUTION_JWT_SECRET',
    help='JWT secret key used for signing and verifying JSON Web Tokens'
    ' when connecting to execution nodes.',
)
@click.option(
    '--consensus-endpoints',
    type=str,
    envvar='CONSENSUS_ENDPOINTS',
    default=DEFAULT_CONSENSUS_ENDPOINT,
    prompt='Enter the comma separated list of API endpoints for consensus nodes',
    help='Comma separated list of API endpoints for consensus nodes.',
    show_default=True,
)
@click.command(help='Start node manager operator service')
# pylint: disable-next=too-many-arguments,too-many-locals
def node_manager_start(
    consensus_endpoints: str,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    verbose: bool,
    data_dir: str,
    log_level: str,
    log_format: str,
    network: str,
    operator_address: ChecksumAddress,
    max_fee_per_gas_gwei: int | None,
    validator_type: ValidatorType,
    max_validator_balance_gwei: int | None,
    wallet_file: str | None,
    wallet_password_file: str | None,
    keystores_dir: str | None,
    keystores_password_file: str | None,
) -> None:
    network_config = NETWORKS[network]
    vault = network_config.COMMUNITY_VAULT_CONTRACT_ADDRESS
    vault_dir = Path(data_dir) / vault.lower()

    settings.set(
        vault=vault,
        vault_dir=vault_dir,
        network=network,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        verbose=verbose,
        log_level=log_level,
        log_format=log_format,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        validator_type=validator_type,
        max_validator_balance_gwei=(
            Gwei(max_validator_balance_gwei) if max_validator_balance_gwei else None
        ),
        keystores_dir=keystores_dir,
        keystores_password_file=keystores_password_file,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
    )

    try:
        asyncio.run(_start(operator_address))
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def _start(
    operator_address: ChecksumAddress,
) -> None:
    setup_logging()
    await setup_clients()

    if not settings.skip_startup_checks:
        await startup_checks(operator_address)
    try:
        NetworkValidatorCrud().setup()

        keystore = await load_keystore()

        # start operator tasks
        logger.info('Updating oracles cache...')
        await update_oracles_cache()

        logger.info(
            'Started node manager service, polling eligibility for %s',
            operator_address,
        )
        with InterruptHandler() as interrupt_handler:
            await asyncio.gather(
                NodeManagerTask(operator_address=operator_address, keystore=keystore).run(
                    interrupt_handler
                ),
                StateSyncTask(operator_address).run(interrupt_handler),
            )
    finally:
        await close_clients()
