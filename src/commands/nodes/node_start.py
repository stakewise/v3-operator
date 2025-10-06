import asyncio
import logging
from pathlib import Path

import click
import psutil
from eth_typing import ChecksumAddress
from sw_utils import get_consensus_client, get_execution_client

from src.common.clients import setup_clients
from src.common.validators import validate_eth_address
from src.config.config import OperatorConfig
from src.config.networks import NETWORKS
from src.config.settings import LOG_DATE_FORMAT, settings
from src.nodes.exceptions import NodeFailedToStartError
from src.nodes.process import (
    LighthouseProcessBuilder,
    LighthouseVCProcessBuilder,
    ProcessRunner,
    RethProcessBuilder,
)
from src.nodes.status import SyncStatusHistory
from src.nodes.typings import StdStreams

logger = logging.getLogger(__name__)


@click.option(
    '--data-dir',
    default=Path.home() / '.stakewise',
    envvar='DATA_DIR',
    help='Path where the nodes data will be placed',
    type=click.Path(exists=False, file_okay=False, dir_okay=True, path_type=Path),
    show_default=True,
)
@click.option(
    '--no-confirm',
    is_flag=True,
    default=False,
    help='Skips confirmation messages when provided.',
)
@click.option(
    '--vault',
    callback=validate_eth_address,
    envvar='VAULT',
    prompt='Enter your vault address',
    help='Address of the vault to register validators for.',
)
@click.option(
    '--print-execution-logs',
    is_flag=True,
    default=False,
    help='Whether to print execution node logs',
)
@click.option(
    '--print-consensus-logs',
    is_flag=True,
    default=False,
    help='Whether to print consensus node logs',
)
@click.option(
    '--print-validator-logs',
    is_flag=True,
    default=False,
    help='Whether to print validator node logs',
)
@click.command(help='Starts execution, consensus, and validator nodes.')
# pylint: disable=too-many-arguments
def node_start(
    data_dir: Path,
    no_confirm: bool,
    vault: ChecksumAddress,
    print_execution_logs: bool,
    print_consensus_logs: bool,
    print_validator_logs: bool,
) -> None:
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt=LOG_DATE_FORMAT,
        level='INFO',
    )

    operator_config = OperatorConfig(vault, Path(data_dir))
    operator_config.load()

    click.echo('Checking hardware requirements...')
    check_hardware_requirements(
        data_dir=data_dir, network=operator_config.network, no_confirm=no_confirm
    )

    # Minimal settings for the nodes
    settings.set(
        vault=vault,
        network=operator_config.network,
        vault_dir=operator_config.vault_dir,
        nodes_dir=data_dir / operator_config.network / 'nodes',
    )

    # Check that nodes are installed
    check_consensus_node_installed()
    check_execution_node_installed()

    # Start the nodes
    asyncio.run(
        main(
            print_execution_logs=print_execution_logs,
            print_consensus_logs=print_consensus_logs,
            print_validator_logs=print_validator_logs,
        )
    )


async def main(
    print_execution_logs: bool,
    print_consensus_logs: bool,
    print_validator_logs: bool,
) -> None:
    # Setup default clients
    await setup_clients()

    # Create non-retry clients to fail fast
    execution_client = get_execution_client(
        endpoints=settings.execution_endpoints,
        timeout=10,
    )
    consensus_client = get_consensus_client(
        endpoints=settings.consensus_endpoints,
        timeout=10,
    )

    # Create process runners
    reth_runner = _get_reth_runner(print_execution_logs)
    lighthouse_runner = _get_lighthouse_runner(print_consensus_logs)
    lighthouse_vc_runner = _get_lighthouse_vc_runner(print_validator_logs)
    sync_status_history = SyncStatusHistory()

    try:
        await asyncio.gather(
            reth_runner.run(),
            lighthouse_runner.run(),
            lighthouse_vc_runner.run(),
            sync_status_history.update_periodically(
                execution_client=execution_client, consensus_client=consensus_client
            ),
        )
    except NodeFailedToStartError as e:
        click.echo(str(e))
        raise click.Abort() from e
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Handle Ctrl+C
        # Shut down the processes gracefully
        # Do not reraise
        click.echo('Shutting down nodes...')
        await asyncio.gather(
            reth_runner.stop(),
            lighthouse_runner.stop(),
            lighthouse_vc_runner.stop(),
        )
    finally:
        # Handle unexpected error
        # Shut down the processes gracefully
        # Reraise the exception
        if reth_runner.is_alive or lighthouse_runner.is_alive:
            click.echo('Shutting down nodes...')
            await asyncio.gather(
                reth_runner.stop(),
                lighthouse_runner.stop(),
                lighthouse_vc_runner.stop(),
            )


def check_hardware_requirements(data_dir: Path, network: str, no_confirm: bool) -> None:
    # Check memory requirements
    mem = psutil.virtual_memory()
    mem_total_gb = mem.total / (1024**3)
    min_memory_gb = NETWORKS[network].NODE_CONFIG.MIN_MEMORY_GB

    if mem_total_gb < min_memory_gb:
        if not no_confirm and not click.confirm(
            f'At least {min_memory_gb} GB of RAM is recommended to run the nodes.\n'
            f'You have {mem_total_gb:.1f} GB of RAM in total.\n'
            f'Do you want to continue anyway?',
            default=False,
        ):
            raise click.Abort()

    # Check disk space requirements
    disk_usage = psutil.disk_usage(str(data_dir))
    disk_total_tb = disk_usage.total / (1024**4)
    min_disk_tb = NETWORKS[network].NODE_CONFIG.MIN_DISK_SPACE_TB

    if disk_total_tb < min_disk_tb:
        if not no_confirm and not click.confirm(
            f'At least {min_disk_tb} TB of disk space is recommended in the data directory.\n'
            f'You have {disk_total_tb:.1f} TB available at {data_dir}.\n'
            f'Do you want to continue anyway?',
            default=False,
        ):
            raise click.Abort()


def check_execution_node_installed() -> None:
    if not (settings.nodes_dir / 'reth' / 'reth').exists():
        raise click.ClickException(
            'Execution node is not installed. Please run "node-install" command first.'
        )


def check_consensus_node_installed() -> None:
    if not (settings.nodes_dir / 'lighthouse' / 'lighthouse').exists():
        raise click.ClickException(
            'Consensus node is not installed. Please run "node-install" command first.'
        )


def _get_reth_runner(show_output: bool) -> ProcessRunner:
    reth_process_builder = RethProcessBuilder(streams=_build_std_streams(show_output))

    return ProcessRunner(
        process_builder=reth_process_builder,
    )


def _get_lighthouse_runner(show_output: bool) -> ProcessRunner:
    lighthouse_process_builder = LighthouseProcessBuilder(streams=_build_std_streams(show_output))

    return ProcessRunner(
        process_builder=lighthouse_process_builder,
    )


def _get_lighthouse_vc_runner(show_output: bool) -> ProcessRunner:
    lighthouse_vc_process_builder = LighthouseVCProcessBuilder(
        streams=_build_std_streams(show_output),
    )

    return ProcessRunner(
        process_builder=lighthouse_vc_process_builder,
    )


def _build_std_streams(show_output: bool) -> StdStreams:
    """
    Builds standard streams for the process based on the show_output flag.
    """
    if show_output:
        # The value None will make the subprocess
        # inherit the stream from parent process
        return StdStreams(
            stdin=asyncio.subprocess.PIPE,
            stdout=None,
            stderr=asyncio.subprocess.STDOUT,
        )
    return StdStreams(
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
