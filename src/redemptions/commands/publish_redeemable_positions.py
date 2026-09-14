import asyncio
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click
from eth_typing import BlockNumber
from web3 import Web3
from web3.types import Wei

from src.common.clients import build_ipfs_upload_clients, close_clients, setup_clients
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.startup_check import (
    check_execution_nodes_network,
    wait_for_execution_node,
    wait_for_graph_node_sync_to_chain_head,
)
from src.common.utils import log_verbose
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.graph import graph_get_redeemable_allocators
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.typings import Allocator, AllocatorsSnapshot, OsTokenPosition

logger = logging.getLogger(__name__)


@click.option(
    '--allocators-file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar='ALLOCATORS_FILE',
    prompt='Enter the path to the redeemable allocators file',
    help='Path to the redeemable allocators file produced by fetch-redeemable-positions.',
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
@click.command(
    help='Sorts redeemable os token positions by LTV, calculates the Merkle root'
    ' and uploads them to IPFS'
)
# pylint: disable-next=too-many-arguments
def publish_redeemable_positions(
    allocators_file: Path,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    network: str,
    verbose: bool,
    log_level: str,
) -> None:
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
                pool.submit(lambda: asyncio.run(main(allocators_file=allocators_file))).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(main(allocators_file=allocators_file))
            else:
                raise e
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    allocators_file: Path,
) -> None:
    setup_logging()
    await setup_clients()
    await _startup_check()
    try:
        await process(allocators_file=allocators_file)
    finally:
        await close_clients()


async def process(
    allocators_file: Path,
) -> None:
    """
    Load a redeemable allocators snapshot, refresh LTVs at the snapshot block,
    sort positions, calculate the Merkle root and upload them to IPFS.
    """
    with open(allocators_file, encoding='utf-8') as f:
        snapshot = AllocatorsSnapshot.from_dict(json.load(f))
    block_number = snapshot.block_number
    click.echo(f'Positions fetched at block: {block_number}')

    allocators = snapshot.allocators
    await _refresh_ltv(allocators, block_number)

    min_redeemable_shares = Web3.to_wei(snapshot.min_os_token_position_amount_gwei, 'gwei')
    os_token_positions = create_os_token_positions(allocators, min_redeemable_shares)
    if not os_token_positions:
        logger.info('No redeemable os token positions to upload, exiting...')
        return

    await _publish_positions(os_token_positions)


async def _refresh_ltv(allocators: list[Allocator], block_number: BlockNumber) -> None:
    """
    LTV is refetched from the subgraph at the snapshot block so sorting reflects the subgraph
    state at that block even if the snapshot file was edited by hand.
    """
    current_allocators = await graph_get_redeemable_allocators(block_number)
    current_ltv_by_position = {
        (allocator.address, vault_position.address): vault_position.ltv
        for allocator in current_allocators
        for vault_position in allocator.vault_os_token_positions
    }
    for allocator in allocators:
        for vault_position in allocator.vault_os_token_positions:
            current_ltv = current_ltv_by_position.get((allocator.address, vault_position.address))
            if current_ltv is None:
                logger.warning(
                    'No current LTV found for allocator %s at vault %s,'
                    ' keeping the snapshot LTV %s',
                    allocator.address,
                    vault_position.address,
                    vault_position.ltv,
                )
                continue
            vault_position.ltv = current_ltv


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

    # calculate merkle root
    nonce = await os_token_redeemer_contract.nonce()
    tree = PositionsMerkleTree(os_token_positions, leaf_nonce=nonce)
    click.echo(f'Generated Merkle Tree root: {tree.root}')

    ipfs_upload_client = build_ipfs_upload_clients()
    ipfs_hash = await ipfs_upload_client.upload_json(positions_payload)
    click.echo(f'Redeemable os token positions uploaded to IPFS: hash={ipfs_hash}')


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
