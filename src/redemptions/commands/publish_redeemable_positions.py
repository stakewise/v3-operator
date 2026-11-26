import asyncio
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click

from src.common.clients import close_clients, setup_clients
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.startup_check import (
    check_execution_nodes_network,
    wait_for_execution_node,
)
from src.common.utils import log_verbose
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.redemptions.commands.update_redeemable_positions import publish_positions
from src.redemptions.typings import OsTokenPosition

logger = logging.getLogger(__name__)


@click.option(
    '--positions-file',
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar='POSITIONS_FILE',
    required=True,
    help='Path to the JSON file with redeemable os token positions.',
)
@click.option(
    '--dry-run',
    is_flag=True,
    default=False,
    help='Compute and print the Merkle root without uploading the positions to IPFS.',
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
    help='Computes the Merkle root of a prepared redeemable os token positions file'
    ' and uploads it to IPFS'
)
# pylint: disable-next=too-many-arguments
def publish_redeemable_positions(
    positions_file: Path,
    dry_run: bool,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    network: str,
    verbose: bool,
    log_level: str,
) -> None:
    settings.set(
        # No specific vault address is set — redemptions are published across all vaults.
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
                pool.submit(
                    lambda: asyncio.run(main(positions_file=positions_file, dry_run=dry_run))
                ).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(main(positions_file=positions_file, dry_run=dry_run))
            else:
                raise e
    except click.ClickException:
        raise
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(positions_file: Path, dry_run: bool) -> None:
    setup_logging()
    os_token_positions = _load_positions(positions_file)
    await setup_clients()
    try:
        await _startup_check()
        await publish_positions(os_token_positions, dry_run=dry_run)
    finally:
        await close_clients()


def _load_positions(positions_file: Path) -> list[OsTokenPosition]:
    try:
        with open(positions_file, encoding='utf-8') as f:
            payload = json.load(f)
        if not isinstance(payload, list):
            raise click.ClickException('The positions file must contain a JSON list')
        os_token_positions = [
            OsTokenPosition.from_dict(item, index=index) for index, item in enumerate(payload)
        ]
    except (ValueError, KeyError, TypeError) as e:
        raise click.ClickException(f'Invalid positions file {positions_file}: {e!r}') from e

    if not os_token_positions:
        raise click.ClickException(f'No positions found in {positions_file}')

    seen: set[tuple[str, str]] = set()
    for position in os_token_positions:
        key = (position.owner, position.vault)
        if key in seen:
            raise click.ClickException(
                f'Duplicate position for owner {position.owner} and vault {position.vault}'
            )
        seen.add(key)
    return os_token_positions


async def _startup_check() -> None:
    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking execution nodes network...')
    await check_execution_nodes_network()
