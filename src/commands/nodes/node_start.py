import asyncio
import logging
from pathlib import Path

import click
import psutil

from src.config.networks import AVAILABLE_NETWORKS, NETWORKS
from src.config.settings import DEFAULT_NETWORK, LOG_DATE_FORMAT
from src.nodes.process import (
    LighthouseProcessBuilder,
    ProcessRunner,
    RethProcessBuilder,
)

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
    '--no-confirm',
    is_flag=True,
    default=False,
    help='Skips confirmation messages when provided.',
)
@click.command(help='Starts execution and consensus nodes.')
def node_start(data_dir: Path, network: str, no_confirm: bool) -> None:
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt=LOG_DATE_FORMAT,
        level='INFO',
    )
    # Create the data directory if it does not exist
    # Also the data directory could be created by the `init` command
    data_dir.mkdir(parents=True, exist_ok=True)

    click.echo('Checking hardware requirements...')
    _check_hardware_requirements(data_dir=data_dir, network=network, no_confirm=no_confirm)

    asyncio.run(main(data_dir=data_dir, network=network))


async def main(data_dir: Path, network: str) -> None:
    reth_process_builder = RethProcessBuilder(network=network, data_dir=data_dir)
    lighthouse_process_builder = LighthouseProcessBuilder(network=network, data_dir=data_dir)

    reth_runner = ProcessRunner(
        process_builder=reth_process_builder,
        min_restart_interval=60,  # seconds
    )
    lighthouse_runner = ProcessRunner(
        process_builder=lighthouse_process_builder,
        min_restart_interval=60,  # seconds
    )

    try:
        await asyncio.gather(
            reth_runner.run(),
            lighthouse_runner.run(),
        )
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Handle Ctrl+C
        # Shut down the processes gracefully
        # Do not reraise
        click.echo('Shutting down nodes...')
        await asyncio.gather(
            reth_runner.stop(),
            lighthouse_runner.stop(),
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
            )


def _check_hardware_requirements(data_dir: Path, network: str, no_confirm: bool) -> None:
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
