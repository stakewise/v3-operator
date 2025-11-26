import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from sw_utils import InterruptHandler
from web3.types import Gwei

from src.commands.start.base import log_start, setup_sentry
from src.common.checks import wait_execution_catch_up_consensus
from src.common.clients import setup_clients
from src.common.consensus import get_chain_finalized_head
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.protocol_config import update_oracles_cache
from src.common.utils import log_verbose
from src.common.validators import validate_eth_addresses
from src.config.networks import AVAILABLE_NETWORKS, GNOSIS, MAINNET, NETWORKS
from src.config.settings import (
    DEFAULT_META_VAULT_UPDATE_INTERVAL,
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
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--wallet-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_FILE',
    help='Absolute path to the wallet. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--meta-vault-min-deposit-amount-gwei',
    type=int,
    envvar='META_VAULT_MIN_DEPOSIT_AMOUNT',
    help=f'Minimum amount in gwei to deposit into subvaults for meta vault.'
    f' The default is {DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI}',
    default=DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
)
@click.option(
    '--meta-vault-update-interval',
    type=int,
    envvar='META_VAULT_UPDATE_INTERVAL',
    help=f'Interval in seconds to process subvault states and deposits.'
    f' The default is {DEFAULT_META_VAULT_UPDATE_INTERVAL}',
    default=DEFAULT_META_VAULT_UPDATE_INTERVAL,
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter the comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
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
    prompt='Enter the comma separated list of API endpoints for consensus nodes',
    help='Comma separated list of API endpoints for consensus nodes.',
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
    help='The network of the vault. Default is the network specified at "init" command.',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(
    help='Performs a vault validators consolidation from 0x01 validators to 0x02 validator. '
    'Switches a validator from 0x01 to 0x02 if the source and target keys are identical.'
)
# pylint: disable-next=too-many-arguments,too-many-locals
def process_metavaults(
    vaults: str,
    consensus_endpoints: str,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    network: str,
    verbose: bool,
    log_level: str,
    log_format: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
    max_fee_per_gas_gwei: int | None,
    meta_vault_min_deposit_amount_gwei: int,
    meta_vault_update_interval: int,
) -> None:
    vault_addresses = [to_checksum_address(address) for address in vaults.split(',')]
    settings.set(
        # mock vault and vault_dir
        vault=vault_addresses[0],
        vault_dir=Path.home() / '.stakewise',

        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_endpoint=graph_endpoint,
        verbose=verbose,
        network=network,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        log_level=log_level,
        log_format=log_format,
        meta_vault_min_deposit_amount_gwei=Gwei(meta_vault_min_deposit_amount_gwei),
        meta_vault_update_interval=meta_vault_update_interval,
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

    chain_state = await get_chain_finalized_head()
    await wait_execution_catch_up_consensus(chain_state)

    logger.info('Updating oracles cache...')
    await update_oracles_cache()

    logger.info('Started operator service')
    with InterruptHandler() as interrupt_handler:
        await ProcessMetaVaultTask(vaults).run(interrupt_handler)
