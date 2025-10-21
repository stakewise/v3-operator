import asyncio
import json
import logging
from pathlib import Path

import click
from sw_utils import get_consensus_client, get_execution_client

from src.common.logging import setup_logging
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import DEFAULT_NETWORK, LOG_PLAIN, settings
from src.nodes.status import (
    get_consensus_node_status,
    get_execution_node_status,
    get_validator_activity_stats,
)

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
    help='The network of your vault.',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.option(
    '--output-format',
    default='text',
    envvar='OUTPUT_FORMAT',
    help='The output format for the command.',
    type=click.Choice(OUTPUT_FORMATS, case_sensitive=False),
    show_default=True,
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--enable-file-logging',
    help='Enable logging command output to a file in the nodes directory. Default is false.',
    envvar='ENABLE_FILE_LOGGING',
    is_flag=True,
    default=False,
)
@click.command(help='Displays the status of the nodes.', name='node-status')
def node_status_command(
    data_dir: Path, network: str, output_format: str, verbose: bool, enable_file_logging: bool
) -> None:
    # Using zero address since vault directory is not required for this command
    vault_address = ZERO_CHECKSUM_ADDRESS

    # Minimal settings for the nodes
    settings.set(
        vault=vault_address,
        network=network,
        vault_dir=data_dir / vault_address,
        nodes_dir=data_dir / network / 'nodes',
        verbose=verbose,
        log_format=LOG_PLAIN,
        enable_file_logging=enable_file_logging,
        log_file_path=data_dir / 'operator.log',
    )
    setup_logging()

    asyncio.run(main(output_format))


async def main(output_format: str) -> None:
    # Create non-retry clients to fail fast
    execution_client = get_execution_client(
        endpoints=settings.execution_endpoints,
        timeout=10,
    )
    consensus_client = get_consensus_client(
        endpoints=settings.consensus_endpoints,
        timeout=10,
    )

    # Get node statuses concurrently
    consensus_node_status, execution_node_status = await asyncio.gather(
        get_consensus_node_status(consensus_client),
        get_execution_node_status(execution_client),
    )

    if consensus_node_status.get('is_syncing') is False:
        validator_activity_stats = await get_validator_activity_stats(consensus_client)
    else:
        validator_activity_stats = {}

    # Log statuses
    _log_nodes_status(
        execution_node_status=execution_node_status,
        consensus_node_status=consensus_node_status,
        validator_activity_stats=validator_activity_stats,
        output_format=output_format,
    )


def _log_nodes_status(
    execution_node_status: dict,
    consensus_node_status: dict,
    validator_activity_stats: dict,
    output_format: str,
) -> None:
    if output_format == 'json':
        _log_nodes_status_json(
            execution_node_status=execution_node_status,
            consensus_node_status=consensus_node_status,
            validator_activity_stats=validator_activity_stats,
        )
    else:
        _log_nodes_status_text(
            execution_node_status=execution_node_status,
            consensus_node_status=consensus_node_status,
            validator_activity_stats=validator_activity_stats,
        )


def _log_nodes_status_json(
    execution_node_status: dict, consensus_node_status: dict, validator_activity_stats: dict
) -> None:
    combined_status = {
        'consensus_node': consensus_node_status,
        'execution_node': execution_node_status,
        'validator_activity': validator_activity_stats,
    }
    click.echo(json.dumps(combined_status))


def _log_nodes_status_text(
    execution_node_status: dict, consensus_node_status: dict, validator_activity_stats: dict
) -> None:
    _log_consensus_node_status_text(node_status=consensus_node_status)
    _log_execution_node_status_text(node_status=execution_node_status)

    if validator_activity_stats:
        _log_validator_activity_stats_text(validator_activity_stats=validator_activity_stats)


def _log_consensus_node_status_text(node_status: dict) -> None:
    if not node_status:
        click.echo('Consensus node status: unavailable.')
        return

    status_message = [
        'Consensus node status:',
        f'  Is syncing: {node_status['is_syncing']}',
        f'  Head slot: {node_status['head_slot']}',
        f'  Sync distance: {node_status['sync_distance']}',
    ]
    eta = node_status.get('eta')

    if node_status['is_syncing'] and eta is not None:
        status_message.append(f'  Estimated time to sync: {_format_eta(eta)}')
    elif node_status['is_syncing'] and eta is None:
        status_message.append('  Estimated time to sync: unavailable')

    click.echo('\n'.join(status_message))


def _log_execution_node_status_text(node_status: dict) -> None:
    if not node_status:
        click.echo('Execution node status: unavailable.')
        return

    status_message = [
        'Execution node status:',
        f'  Is syncing: {node_status['is_syncing']}',
        f'  Block number: {node_status['latest_block_number']}',
        f'  Sync distance: {node_status['sync_distance']}',
    ]
    eta = node_status.get('eta')

    if node_status['is_syncing'] and eta is not None:
        status_message.append(f'  Estimated time to sync: {_format_eta(eta)}')
    elif node_status['is_syncing'] and eta is None:
        status_message.append('  Estimated time to sync: unavailable')

    click.echo('\n'.join(status_message))


def _format_eta(eta: int) -> str:
    if eta == 0:
        return '0'

    minutes, seconds = divmod(eta, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)

    parts = []
    if days > 0:
        parts.append(f'{days}d')
    if hours > 0:
        parts.append(f'{hours}h')
    if minutes > 0:
        parts.append(f'{minutes}m')
    if seconds > 0:
        parts.append(f'{seconds}s')

    return ' '.join(parts)


def _log_validator_activity_stats_text(validator_activity_stats: dict) -> None:
    click.echo(
        f'Validator activity:\n'
        f'  Active validators: {validator_activity_stats['active']}\n'
        f'  Total validators: {validator_activity_stats['total']}'
    )
