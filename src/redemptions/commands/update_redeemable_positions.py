import asyncio
import json
import logging
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress
from sw_utils import OsTokenConverter
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import (
    build_ipfs_upload_clients,
    close_clients,
    execution_client,
    setup_clients,
)
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.startup_check import (
    check_execution_nodes_network,
    wait_for_execution_node,
    wait_for_graph_node_sync_to_chain_head,
)
from src.common.utils import get_current_timestamp, log_verbose
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.redemptions.api_client import (
    API_SLEEP_TIMEOUT,
    API_SOURCES,
    DEBANK_API_SOURCE,
    RABBY_API_SOURCE,
    APIClient,
)
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.graph import (
    graph_get_leverage_positions,
    graph_get_os_token_holders,
    graph_get_redeemable_allocators,
)
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.os_token_converter import create_os_token_converter
from src.redemptions.typings import (
    Allocator,
    ApiConfig,
    LeverageStrategyPosition,
    OsTokenPosition,
)

logger = logging.getLogger(__name__)


@click.option(
    '--api-access-key',
    type=str,
    envvar='API_ACCESS_KEY',
    help='Access key for the DeBank API. Required when api-source is debank.',
)
@click.option(
    '--api-source',
    type=click.Choice(list(API_SOURCES.keys()), case_sensitive=False),
    default=RABBY_API_SOURCE,
    show_default=True,
    envvar='API_SOURCE',
    help='API source to use for fetching locked os token positions.',
)
@click.option(
    '--api-sleep-timeout',
    type=float,
    default=API_SLEEP_TIMEOUT,
    show_default=True,
    envvar='API_SLEEP_TIMEOUT',
    help='Sleep timeout in seconds between API calls to avoid rate limiting.',
)
@click.option(
    '--min-os-token-position-amount-gwei',
    type=int,
    default=0,
    show_default=True,
    envvar='MIN_OS_TOKEN_POSITION_AMOUNT_GWEI',
    help='Process positions only if the amount of minted os token in Gwei'
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
    help='The network for redeemable os token positions.',
    prompt='Enter the network name',
    envvar='NETWORK',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Updates redeemable os token positions')
# pylint: disable-next=too-many-arguments,too-many-locals
def update_redeemable_positions(
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    network: str,
    verbose: bool,
    log_level: str,
    min_os_token_position_amount_gwei: int,
    api_sleep_timeout: float,
    api_source: str,
    api_access_key: str | None,
) -> None:
    if api_source == DEBANK_API_SOURCE and not api_access_key:
        api_access_key = click.prompt('Enter the DeBank API access key')
    api_config = ApiConfig(
        source=api_source,
        sleep_timeout=api_sleep_timeout,
        access_key=api_access_key,
    )
    settings.set(
        # No specific vault address is set — redemptions are updated across all vaults.
        vault=ZERO_CHECKSUM_ADDRESS,
        vault_dir=Path.home() / '.stakewise',
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_endpoint=graph_endpoint,
        verbose=verbose,
        network=network,
        log_level=log_level,
    )
    try:
        # Try-catch to enable async calls in test - an event loop
        #  will already be running in that case
        try:
            asyncio.get_running_loop()
            # we need to create a separate thread so we can block before returning
            with ThreadPoolExecutor(1) as pool:
                pool.submit(
                    lambda: asyncio.run(
                        main(
                            min_os_token_position_amount_gwei=Gwei(
                                min_os_token_position_amount_gwei
                            ),
                            api_config=api_config,
                        )
                    )
                ).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(
                    main(
                        min_os_token_position_amount_gwei=Gwei(min_os_token_position_amount_gwei),
                        api_config=api_config,
                    )
                )
            else:
                raise e
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    min_os_token_position_amount_gwei: Gwei,
    api_config: ApiConfig,
) -> None:
    setup_logging()
    await setup_clients()
    await _startup_check()
    try:
        await process(
            min_os_token_position_amount_gwei=min_os_token_position_amount_gwei,
            api_config=api_config,
        )
    finally:
        await close_clients()


async def process(
    min_os_token_position_amount_gwei: Gwei,
    api_config: ApiConfig,
) -> None:
    """
    Fetch redeemable os token positions, calculate kept os token amounts and upload to IPFS.
    """
    finalized_block = await execution_client.eth.get_block('finalized')
    block_number = finalized_block['number']

    allocators = await _fetch_allocators(block_number)

    logger.info('Fetching boosted positions from the subgraph...')
    leverage_positions = await graph_get_leverage_positions(block_number)
    allocators = _exclude_boost_proxies(allocators, leverage_positions)
    await _apply_boost(allocators, leverage_positions, block_number)

    # filter zero positions. Filter before kept shares calculation to reduce api calls
    min_redeemable_shares = Web3.to_wei(min_os_token_position_amount_gwei, 'gwei')
    allocators = _filter_min_redeemable_shares(allocators, min_redeemable_shares)

    if not allocators:
        logger.info('No allocators with redeemable shares above the threshold found, exiting...')
        return

    logger.info('Fetching kept tokens for %s addresses', len(allocators))
    api_client = APIClient.build_client(api_config)
    await populate_kept_shares(allocators, block_number, api_client)
    logger.info('Fetched kept tokens for %s addresses...', len(allocators))

    os_token_positions = create_os_token_positions(allocators, min_redeemable_shares)
    if not os_token_positions:
        logger.info('No redeemable os token positions to upload, exiting...')
        return

    await _publish_positions(os_token_positions)


async def _fetch_allocators(block_number: BlockNumber) -> list[Allocator]:
    logger.info('Fetching allocators from the subgraph...')
    allocators = await graph_get_redeemable_allocators(block_number)
    logger.info('Fetched %s allocators from the subgraph', len(allocators))
    return allocators


def _exclude_boost_proxies(
    allocators: list[Allocator],
    leverage_positions: list[LeverageStrategyPosition],
) -> list[Allocator]:
    """Boost proxies hold minted osToken on behalf of a user; they are never allocators."""
    boost_proxies = {pos.proxy for pos in leverage_positions}
    logger.info('Found %s proxy positions to exclude', len(boost_proxies))
    return [a for a in allocators if a.address not in boost_proxies]


async def _apply_boost(
    allocators: list[Allocator],
    leverage_positions: list[LeverageStrategyPosition],
    block_number: BlockNumber,
) -> None:
    os_token_converter = await create_os_token_converter(block_number)
    boost_os_token_shares = await calculate_boost_os_token_shares(
        users={a.address for a in allocators},
        leverage_positions=leverage_positions,
        os_token_converter=os_token_converter,
    )
    _distribute_boosted_shares(allocators, boost_os_token_shares)


def _filter_min_redeemable_shares(
    allocators: list[Allocator],
    min_redeemable_shares: Wei,
) -> list[Allocator]:
    result = []
    for allocator in allocators:
        vault_os_token_positions = [
            vault_position
            for vault_position in allocator.vault_os_token_positions
            if vault_position.redeemable_shares >= min_redeemable_shares
        ]
        # drop allocators left with no vault positions so populate_kept_shares
        # doesn't waste a rate-limited api call on a guaranteed-zero position
        if not vault_os_token_positions:
            continue
        allocator.vault_os_token_positions = vault_os_token_positions
        result.append(allocator)
    return result


async def _publish_positions(os_token_positions: list[OsTokenPosition]) -> None:
    total_redeemable = sum(p.leaf_shares for p in os_token_positions)
    logger.info(
        'Created %(count)s redeemable os token positions. '
        'Total redeemed %(os_token_symbol)s amount: '
        '%(total_redeemable)s (%(total_redeemable_eth).5f %(os_token_symbol)s)',
        {
            'count': len(os_token_positions),
            'os_token_symbol': settings.network_config.OS_TOKEN_BALANCE_SYMBOL,
            'total_redeemable': total_redeemable,
            'total_redeemable_eth': Web3.from_wei(total_redeemable, 'ether'),
        },
    )
    positions_payload = [p.as_dict() for p in os_token_positions]
    positions_file = _save_positions_to_file(positions_payload)
    click.echo(f'Redeemable os token positions saved to {positions_file}')

    # calculate merkle root
    nonce = await os_token_redeemer_contract.nonce()
    tree = PositionsMerkleTree(os_token_positions, leaf_nonce=nonce)
    click.echo(f'Generated Merkle Tree root: {tree.root}')

    ipfs_upload_client = build_ipfs_upload_clients()
    ipfs_hash = await ipfs_upload_client.upload_json(positions_payload)
    click.echo(f'Redeemable os token positions uploaded to IPFS: hash={ipfs_hash}')


async def populate_kept_shares(
    allocators: list[Allocator],
    block_number: BlockNumber,
    api_client: APIClient | None,
) -> None:
    """Sets ``wallet_shares`` for every allocator, then ``locked_shares`` via the API — but only
    for allocators whose wallet balance doesn't already cover their redeemable amount, and only
    when the network is API-supported."""
    logger.info(
        'Fetching %s balances from the subgraph...', settings.network_config.OS_TOKEN_BALANCE_SYMBOL
    )
    os_token_holders = await graph_get_os_token_holders(block_number)
    for allocator in allocators:
        allocator.wallet_shares = os_token_holders.get(allocator.address, Wei(0))

    if api_client is None:
        return

    # do not fetch data from api if all os token are in the wallet
    api_allocators = [a for a in allocators if a.total_redeemable_shares >= a.wallet_shares]
    if not api_allocators:
        return

    logger.info(
        'Fetching locked %s from %s API for %s addresses...',
        settings.network_config.OS_TOKEN_BALANCE_SYMBOL,
        api_client.source,
        len(api_allocators),
    )
    with click.progressbar(
        api_allocators,
        label='Fetching os token amount locked in protocols from the api:\t\t',
        show_percent=False,
        show_pos=True,
    ) as progress_bar:
        for index, allocator in enumerate(progress_bar):
            if index:
                await asyncio.sleep(api_client.sleep_timeout)  # to avoid rate limiting
            allocator.locked_shares = await api_client.get_protocols_locked_os_token(
                address=allocator.address
            )


async def calculate_boost_os_token_shares(
    users: set[ChecksumAddress],
    leverage_positions: list[LeverageStrategyPosition],
    os_token_converter: OsTokenConverter,
) -> dict[tuple[ChecksumAddress, ChecksumAddress], Wei]:
    boosted_positions: defaultdict[tuple[ChecksumAddress, ChecksumAddress], Wei] = defaultdict(
        lambda: Wei(0)
    )
    for position in leverage_positions:
        if position.user not in users:
            continue
        position_os_token_shares = Wei(
            position.os_token_shares
            + position.exiting_os_token_shares
            + os_token_converter.to_shares(position.assets)
            + os_token_converter.to_shares(position.exiting_assets)
        )
        boosted_positions[position.user, position.vault] = Wei(
            boosted_positions[position.user, position.vault] + position_os_token_shares
        )

    return boosted_positions


def create_os_token_positions(
    allocators: list[Allocator],
    min_redeemable_shares: Wei,
) -> list[OsTokenPosition]:
    """
    Split each allocator's redeemable shares across its vaults and sort the resulting
    positions by ltv descending, then amount descending.
    """
    slices = [
        vault_slice
        for allocator in allocators
        for vault_slice in allocator.iter_vault_slices(min_redeemable_shares)
    ]
    slices.sort(key=lambda s: (s.vault_position.ltv, s.amount), reverse=True)
    return [
        OsTokenPosition(
            owner=s.allocator.address,
            vault=s.vault_position.address,
            leaf_shares=s.amount,
        )
        for s in slices
    ]


def _save_positions_to_file(positions_payload: list[dict]) -> Path:
    timestamp = get_current_timestamp()
    positions_file = Path(f'redeemable_positions_{timestamp}.json')
    with open(positions_file, 'w', encoding='utf-8') as f:
        json.dump(positions_payload, f, indent=2)
    return positions_file


def _distribute_boosted_shares(
    allocators: list[Allocator],
    boost_os_token_shares: dict[tuple[ChecksumAddress, ChecksumAddress], Wei],
) -> None:
    """
    osToken is fungible, so boosted shares aren't necessarily minted at the same vault the
    leverage strategy borrows against. Match against the same-vault mint first; store
    whatever can't be matched there as the allocator residual instead of dropping it.
    """
    allocators_by_address = {a.address: a for a in allocators}
    for (user, vault), boosted_amount in boost_os_token_shares.items():
        allocator = allocators_by_address.get(user)
        if allocator is None:
            continue
        vault_position = allocator.get_vault_position(vault)
        matched = Wei(0)
        if vault_position:
            matched = min(vault_position.minted_shares, boosted_amount)
            vault_position.boosted_shares = matched
        allocator.residual_boosted_shares = Wei(
            allocator.residual_boosted_shares + boosted_amount - matched
        )


async def _startup_check() -> None:
    """Verify connectivity to execution nodes, the graph node, and IPFS upload clients."""
    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking execution nodes network...')
    await check_execution_nodes_network()

    logger.info('Checking connection to graph node...')
    await wait_for_graph_node_sync_to_chain_head()

    logger.info('Checking IPFS upload clients...')
    await _check_ipfs_upload_clients()


async def _check_ipfs_upload_clients() -> None:
    ipfs_upload_client = build_ipfs_upload_clients()
    ipfs_hash = await ipfs_upload_client.upload_json({'a': 'b'})
    logger.info('Connected to IPFS upload clients. Test hash: %s', ipfs_hash)
