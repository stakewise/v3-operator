import asyncio
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click
from eth_typing import ChecksumAddress

from src.common.clients import build_ipfs_upload_clients, close_clients, setup_clients
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.startup_check import (
    check_execution_nodes_network,
    wait_for_execution_node,
)
from src.common.utils import log_verbose
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.typings import OsTokenPosition, RedeemablePositionsSnapshot

logger = logging.getLogger(__name__)


@click.option(
    '--positions-file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar='POSITIONS_FILE',
    prompt='Enter the path to the redeemable positions file',
    help='Path to the redeemable positions file produced by fetch-redeemable-positions.',
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
    positions_file: Path,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
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
                pool.submit(lambda: asyncio.run(main(positions_file=positions_file))).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(main(positions_file=positions_file))
            else:
                raise e
    except click.ClickException:
        raise
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    positions_file: Path,
) -> None:
    setup_logging()
    snapshot = _load_snapshot(positions_file)
    await setup_clients()
    await _startup_check()
    try:
        await process(snapshot=snapshot)
    finally:
        await close_clients()


async def process(
    snapshot: RedeemablePositionsSnapshot,
) -> None:
    """
    Sort a redeemable positions snapshot, calculate the Merkle root and upload it to IPFS.
    """
    click.echo(f'Positions fetched at block: {snapshot.block_number}')

    positions = snapshot.positions
    if not positions:
        logger.info('No redeemable os token positions to upload, exiting...')
        return

    # the file may have been hand-edited, so re-sorting keeps the leaf order deterministic
    positions = sorted(positions, key=lambda p: (p.ltv, p.leaf_shares), reverse=True)

    await _publish_positions(positions)


def _load_snapshot(positions_file: Path) -> RedeemablePositionsSnapshot:
    try:
        with open(positions_file, encoding='utf-8') as f:
            snapshot = RedeemablePositionsSnapshot.from_dict(json.load(f))
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        raise click.ClickException(f'Invalid positions file {positions_file}: {e!r}') from e
    _validate_positions(positions_file, snapshot.positions)
    return snapshot


def _validate_positions(positions_file: Path, positions: list[OsTokenPosition]) -> None:
    # the file may be hand-edited between fetch and publish, so copy-paste duplicates and
    # sign mistakes must be rejected here, before any network work
    seen_owner_vault_pairs: set[tuple[ChecksumAddress, ChecksumAddress]] = set()
    for position in positions:
        if position.leaf_shares <= 0:
            raise click.ClickException(
                f'Invalid positions file {positions_file}: position #{position.index} '
                f'({position.owner}, {position.vault}) has non-positive leaf_shares '
                f'{position.leaf_shares}'
            )
        owner_vault_pair = (position.owner, position.vault)
        if owner_vault_pair in seen_owner_vault_pairs:
            raise click.ClickException(
                f'Invalid positions file {positions_file}: duplicate position #{position.index} '
                f'for owner {position.owner} in vault {position.vault}'
            )
        seen_owner_vault_pairs.add(owner_vault_pair)


async def _publish_positions(os_token_positions: list[OsTokenPosition]) -> None:
    positions_payload = [p.as_dict() for p in os_token_positions]

    # calculate merkle root
    nonce = await os_token_redeemer_contract.nonce()
    tree = PositionsMerkleTree(os_token_positions, leaf_nonce=nonce)
    click.echo(f'Generated Merkle Tree root: {tree.root}')

    ipfs_upload_client = build_ipfs_upload_clients()
    ipfs_hash = await ipfs_upload_client.upload_json(positions_payload)
    click.echo(f'Redeemable os token positions uploaded to IPFS: hash={ipfs_hash}')


async def _startup_check() -> None:
    """Verify connectivity to execution nodes and IPFS upload clients."""
    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking execution nodes network...')
    await check_execution_nodes_network()

    logger.info('Checking IPFS upload clients...')
    await _check_ipfs_upload_clients()


async def _check_ipfs_upload_clients() -> None:
    ipfs_upload_client = build_ipfs_upload_clients()
    ipfs_hash = await ipfs_upload_client.upload_json({'a': 'b'})
    logger.info('Connected to IPFS upload clients. Test hash: %s', ipfs_hash)
