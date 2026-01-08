import asyncio
import logging
import sys
from collections import defaultdict
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress
from web3 import Web3
from web3.types import Wei

from src.common.clients import (
    build_ipfs_upload_clients,
    execution_client,
    setup_clients,
)
from src.common.contracts import Erc20Contract
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.redeem.api_client import APIClient
from src.redeem.graph import graph_get_allocators, graph_get_leverage_positions_proxies
from src.redeem.typings import Allocator, RedeemablePosition

logger = logging.getLogger(__name__)


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
    '--graph-endpoint',
    type=str,
    envvar='GRAPH_ENDPOINT',
    help='API endpoint for graph node.',
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
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--network',
    help='The network of the meta vaults.',
    prompt='Enter the network name',
    envvar='NETWORK',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(
    help='Performs a vault validators consolidation from 0x01 validators to 0x02 validator. '
    'Switches a validator from 0x01 to 0x02 if the source and target keys are identical.',
)
# pylint: disable-next=too-many-arguments
def update_redeemable_positions(
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    network: str,
    verbose: bool,
    log_level: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
) -> None:
    settings.set(
        vault=ZERO_CHECKSUM_ADDRESS,
        vault_dir=Path.home() / '.stakewise',
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_endpoint=graph_endpoint,
        verbose=verbose,
        network=network,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        log_level=log_level,
    )
    try:
        asyncio.run(main())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main() -> None:
    """
    Fetch redeemable positions, calculate kept os token amounts and upload to IPFS.
    """
    setup_logging()
    await setup_clients()
    block_number = await execution_client.eth.block_number
    allocators = await graph_get_allocators(block_number)

    # filter
    boost_proxies = await graph_get_leverage_positions_proxies(block_number)
    logger.info('Found %s boost positions to exclude', len(boost_proxies))
    allocators = [a for a in allocators if a.minted_shares > 0 and a.address not in boost_proxies]
    logger.info('Filtered allocators count: %s', len(allocators))

    user_addresses = set(allocator.address for allocator in allocators)
    logger.info('Fetching kept tokens for %s addresses...', len(user_addresses))

    kept_tokens = await get_kept_tokens(list(user_addresses), block_number)
    redeemable_positions: list[RedeemablePosition] = []
    for allocator in allocators:
        kept_token = kept_tokens.get(allocator.address, Wei(0))  # 0?
        amount = min(allocator.minted_shares, kept_token)
        if amount > 0:
            redeemable_positions.append(
                RedeemablePosition(
                    owner=allocator.address,
                    vault=allocator.vault,
                    amount=Wei(allocator.minted_shares - amount),
                )
            )
            kept_tokens[allocator.address] = Wei(kept_tokens[allocator.address] - amount)
    logger.info('Fetched kept tokens for %s addresses...', {len(user_addresses)})

    click.confirm(
        'Proceed consolidation?',
        default=True,
        abort=True,
    )
    ipfs_upload_client = build_ipfs_upload_clients()
    ipfs_hash = await ipfs_upload_client.upload_json([p.as_dict() for p in redeemable_positions])
    click.echo(f'Redeemable position uploaded to IPFS: hash={ipfs_hash}')


async def get_kept_tokens(
    user_addresses: list[ChecksumAddress], block_number: BlockNumber
) -> dict[ChecksumAddress, Wei]:
    wallet_balances = {}

    contract = Erc20Contract(settings.network_config.OS_TOKEN_CONTRACT_ADDRESS)
    for address in user_addresses:
        wallet_balances[address] = await contract.balance(address, block_number)
    api_client = APIClient()
    locked_oseth_per_user: dict[ChecksumAddress, Wei] = {}
    for address in user_addresses:
        locked_os_token = await api_client.get_protocols_locked_locked_os_token(address=address)
        locked_oseth_per_user[address] = locked_os_token

    kept_token = defaultdict(lambda: Wei(0))
    for address, amount in locked_oseth_per_user.items():
        kept_token[address] = amount
    for address, amount in wallet_balances.items():
        kept_token[address] = Wei(kept_token[address] + amount)
    return kept_token
