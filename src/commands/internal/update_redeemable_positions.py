import asyncio
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import cast

import click
from eth_typing import BlockNumber, ChecksumAddress
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import (
    build_ipfs_upload_clients,
    execution_client,
    get_execution_client,
    setup_clients,
)
from src.common.contracts import Erc20Contract, VaultContract
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.config.networks import AVAILABLE_NETWORKS, MAINNET, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.redeem.api_client import API_SLEEP_TIMEOUT, APIClient
from src.redeem.graph import graph_get_allocators, graph_get_leverage_positions
from src.redeem.typings import Allocator, LeverageStrategyPosition, RedeemablePosition

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
    '--min-os-token-position-amount-gwei',
    type=int,
    default=0,
    envvar='MIN_OS_TOKEN_POSITION_AMOUNT_GWEI',
    help='Process positions only if the amount of minted osETH'
    ' is greater than the specified value.',
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
    '--arbitrum-endpoint',
    type=str,
    envvar='ARBITRUM_ENDPOINT',
    help='API endpoint for the execution node on Arbitrum.',
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
@click.command(help='Updates redeemable positions for leverage positions')
# pylint: disable-next=too-many-arguments
def update_redeemable_positions(
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    arbitrum_endpoint: str | None,
    network: str,
    verbose: bool,
    log_level: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
    min_os_token_position_amount_gwei: int,
) -> None:
    if network == MAINNET and not arbitrum_endpoint:
        raise click.BadParameter('arbitrum-endpoint is required for mainnet network')
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
        asyncio.run(
            main(
                arbitrum_endpoint=arbitrum_endpoint,
                min_os_token_position_amount_gwei=Gwei(min_os_token_position_amount_gwei),
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


# pylint: disable-next=too-many-locals
async def main(arbitrum_endpoint: str | None, min_os_token_position_amount_gwei: Gwei) -> None:
    """
    Fetch redeemable positions, calculate kept os token amounts and upload to IPFS.
    """
    setup_logging()
    await setup_clients()
    block_number = await execution_client.eth.block_number
    logger.info('Fetching allocators from the subgraph...')
    allocators = await graph_get_allocators(block_number)
    logger.info('Fetched %s allocators from the subgraph', len(allocators))

    # filter boost proxy positions
    leverage_positions = await graph_get_leverage_positions(block_number)
    boost_proxies = {pos.proxy for pos in leverage_positions}
    logger.info('Found %s proxy positions to exclude', len(boost_proxies))
    allocators = [a for a in allocators if a.address not in boost_proxies]

    # filter boosted positions
    logger.info('Fetching boosted positions from the subgraph...')
    boosted_positions = await get_boosted_positions(
        users=[a.address for a in allocators],
        leverage_positions=leverage_positions,
        block_number=block_number,
    )
    for allocator in allocators:
        if allocator.address not in boosted_positions:
            continue
        for vault_address, boosted_amount in boosted_positions[allocator.address].items():
            for vault_share in allocator.vault_shares:
                if vault_share.address == vault_address:
                    vault_share.minted_shares = Wei(vault_share.minted_shares - boosted_amount)

    # filter zero positions
    min_minted_shares = Web3.to_wei(min_os_token_position_amount_gwei, 'gwei')
    allocators = [a for a in allocators if a.total_shares >= min_minted_shares]

    if not allocators:
        logger.info('No allocators with minted shares above the threshold found, exiting...')
        return

    logger.info('Fetching kept tokens for %s addresses', len(allocators))
    address_to_minted_shares = {a.address: a.total_shares for a in allocators}
    kept_tokens = await get_kept_tokens(address_to_minted_shares, block_number, arbitrum_endpoint)
    logger.info('Fetched kept tokens for %s addresses...', len(address_to_minted_shares))

    redeemable_positions = create_redeemable_positions(allocators, kept_tokens)
    if not redeemable_positions:
        logger.info('No redeemable positions to upload, exiting...')
        return
    logger.info(
        'Created %s redeemable positions. Total redeemed OsEth amount: %s',
        len(redeemable_positions),
        sum(p.amount for p in redeemable_positions),
    )

    click.confirm(
        'Proceed with uploading redeemable positions to IPFS?',
        default=True,
        abort=True,
    )
    ipfs_upload_client = build_ipfs_upload_clients()
    ipfs_hash = await ipfs_upload_client.upload_json([p.as_dict() for p in redeemable_positions])
    click.echo(f'Redeemable position uploaded to IPFS: hash={ipfs_hash}')


async def get_kept_tokens(
    address_to_minted_shares: dict[ChecksumAddress, Wei],
    block_number: BlockNumber,
    arbitrum_endpoint: str | None,
) -> dict[ChecksumAddress, Wei]:
    kept_tokens = defaultdict(lambda: Wei(0))
    logger.info('Fetching OsETH from wallet balances...')

    contract = Erc20Contract(settings.network_config.OS_TOKEN_CONTRACT_ADDRESS)
    for index, address in enumerate(address_to_minted_shares.keys()):
        if index and index % 50 == 0:
            logger.info(
                'Fetched wallet balances for %d/%d addresses', index, len(address_to_minted_shares)
            )
        kept_tokens[address] = await contract.balance(address, block_number)
    # arb wallet balance
    if settings.network_config.OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS != ZERO_CHECKSUM_ADDRESS:
        logger.info('Fetching OsETH from Arbitrum wallet balances...')
        arbitrum_endpoint = cast(str, arbitrum_endpoint)
        arb_execution_client = get_execution_client([arbitrum_endpoint])

        arb_contract = Erc20Contract(
            settings.network_config.OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS,
            execution_client=arb_execution_client,
        )
        for index, address in enumerate(address_to_minted_shares.keys()):
            if index and index % 50 == 0:
                logger.info(
                    'Fetched wallet balances for %d/%d addresses',
                    index,
                    len(address_to_minted_shares),
                )
            arb_balance = await arb_contract.balance(address)
            kept_tokens[address] = Wei(kept_tokens[address] + arb_balance)

    # do not fetch data from api if all os token are on the wallet
    api_addresses = []
    for address in address_to_minted_shares.keys():
        if address_to_minted_shares[address] > kept_tokens[address]:
            api_addresses.append(address)

    if not api_addresses:
        return kept_tokens

    logger.info('Fetching locked OsETH from DeBank API for %s addresses...', len(api_addresses))
    api_client = APIClient()
    locked_oseth_per_user: dict[ChecksumAddress, Wei] = {}
    for address in api_addresses:
        locked_os_token = await api_client.get_protocols_locked_os_token(address=address)
        locked_oseth_per_user[address] = locked_os_token
        kept_tokens[address] = Wei(kept_tokens[address] + locked_os_token)
        await asyncio.sleep(API_SLEEP_TIMEOUT)  # to avoid rate limiting
    return kept_tokens


async def get_boosted_positions(
    users: list[ChecksumAddress],
    leverage_positions: list[LeverageStrategyPosition],
    block_number: BlockNumber,
) -> dict[ChecksumAddress, dict[ChecksumAddress, Wei]]:
    boosted_positions: defaultdict[ChecksumAddress, dict[ChecksumAddress, Wei]] = defaultdict(dict)
    for position in leverage_positions:
        if position.user not in users:
            continue
        vault_contract = VaultContract(position.vault)
        position_os_token_shares = Wei(
            position.os_token_shares
            + await vault_contract.convert_to_shares(position.assets, block_number)
        )
        boosted_positions[position.user][position.vault] = position_os_token_shares

    return boosted_positions


def create_redeemable_positions(
    allocators: list[Allocator], kept_tokens: dict[ChecksumAddress, Wei]
) -> list[RedeemablePosition]:
    """Calculate vault proportions and create redeemable positions"""
    redeemable_positions: list[RedeemablePosition] = []
    for allocator in allocators:
        kept_token = kept_tokens.get(allocator.address, Wei(0))
        amount = min(allocator.total_shares, kept_token)
        if amount <= 0:
            continue

        filled = 0
        for index, (vault_address, proportion) in enumerate(allocator.vaults_proportions.items()):
            # dust handling
            if index == len(allocator.vaults_proportions) - 1:
                vault_amount = int(amount - filled)
            else:
                vault_amount = int(amount * proportion)

            redeemable_positions.append(
                RedeemablePosition(
                    owner=allocator.address,
                    vault=vault_address,
                    amount=Wei(vault_amount),
                )
            )
            filled = filled + vault_amount

    return redeemable_positions
