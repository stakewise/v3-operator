import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from sw_utils import InterruptHandler

from src.common.clients import close_clients, setup_clients
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address
from src.config.networks import AVAILABLE_NETWORKS, NETWORKS
from src.config.settings import (
    DEFAULT_CONSENSUS_ENDPOINT,
    DEFAULT_EXECUTION_ENDPOINT,
    LOG_FORMATS,
    LOG_PLAIN,
    settings,
)
from src.node_manager.tasks import NodeManagerTask

logger = logging.getLogger(__name__)


@click.option(
    '--withdrawals-address',
    callback=validate_eth_address,
    envvar='WITHDRAWALS_ADDRESS',
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
# pylint: disable-next=too-many-arguments
def node_manager_start(
    consensus_endpoints: str,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    verbose: bool,
    data_dir: str,
    log_level: str,
    log_format: str,
    network: str,
    withdrawals_address: ChecksumAddress,
) -> None:
    network_config = NETWORKS[network]
    vault = network_config.ETH_COMMUNITY_VAULT_ADDRESS
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
    )

    try:
        asyncio.run(_start(withdrawals_address))
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def _start(withdrawals_address: ChecksumAddress) -> None:
    setup_logging()
    await setup_clients()
    try:
        logger.info(
            'Started node manager service, polling eligibility for %s',
            withdrawals_address,
        )
        with InterruptHandler() as interrupt_handler:
            await NodeManagerTask(withdrawals_address).run(interrupt_handler)
    finally:
        await close_clients()
