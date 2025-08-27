import asyncio
import json
import logging
from pathlib import Path

import click

from src.common.clients import consensus_client, execution_client, setup_clients
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import DEFAULT_NETWORK, settings

logger = logging.getLogger(__name__)


OUTPUT_FORMATS = ['text', 'json']


@click.option(
    '--data-dir',
    default=Path.home() / '.stakewise',
    envvar='DATA_DIR',
    help='Path where the nodes data will be placed',
    type=click.Path(exists=False, file_okay=False, dir_okay=True, path_type=Path),
    show_default=True,
)
@click.option(
    '--network',
    default=DEFAULT_NETWORK,
    envvar='NETWORK',
    help='The network of your nodes.',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
    show_default=True,
)
@click.option(
    '--output-format',
    default='text',
    envvar='OUTPUT_FORMAT',
    help='The output format for the command.',
    type=click.Choice(OUTPUT_FORMATS, case_sensitive=False),
    show_default=True,
)
@click.command(help='Displays the status of the nodes.')
# pylint: disable=too-many-arguments
def node_status(data_dir: Path, network: str, output_format: str) -> None:
    # Minimal settings for the nodes
    settings.set(
        vaults=[],
        network=network,
        data_dir=data_dir / network,
    )
    asyncio.run(main(output_format))


async def main(output_format: str) -> None:
    await setup_clients()

    consensus_node_status, execution_node_status = await asyncio.gather(
        get_consensus_node_status(), get_execution_node_status()
    )
    log_consensus_node_status(consensus_node_status, output_format)
    log_execution_node_status(execution_node_status, output_format)


async def get_consensus_node_status() -> dict:
    try:
        syncing = await consensus_client.get_syncing()
        sync_distance = syncing['data']['sync_distance']

        data = await consensus_client.get_finality_checkpoint()
        finalized_epoch = data['data']['finalized']['epoch']
    except Exception:
        return {}

    return {
        'is_syncing': syncing['data']['is_syncing'],
        'sync_distance': sync_distance,
        'finalized_epoch': finalized_epoch,
    }


async def get_execution_node_status() -> dict:
    try:
        sync_status = await execution_client.eth.syncing
        if isinstance(sync_status, bool):
            is_syncing = sync_status
        else:
            is_syncing = False
        block_number = await execution_client.eth.block_number
    except Exception:
        return {}

    return {'is_syncing': is_syncing, 'block_number': block_number}


def log_consensus_node_status(consensus_node_status: dict, output_format: str) -> None:
    if output_format == 'json':
        click.echo(json.dumps({'consensus_node': consensus_node_status}))
    else:
        if not consensus_node_status:
            click.echo('Consensus node status: unavailable.')
            return

        click.echo(
            f'Consensus node status:\n'
            f'  Is syncing: {consensus_node_status['is_syncing']}\n'
            f'  Sync distance: {consensus_node_status['sync_distance']}\n'
            f'  Finalized epoch: {consensus_node_status['finalized_epoch']}'
        )


def log_execution_node_status(execution_node_status: dict, output_format: str) -> None:
    if output_format == 'json':
        click.echo(json.dumps({'execution_node': execution_node_status}))
    else:
        if not execution_node_status:
            click.echo('Execution node status: unavailable.')
            return

        click.echo(
            f'Execution node status:\n'
            f'  Is syncing: {execution_node_status['is_syncing']}\n'
            f'  Block number: {execution_node_status['block_number']}'
        )
