import asyncio
import logging
from pathlib import Path

import click

from src.config.networks import AVAILABLE_NETWORKS
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
@click.command(help='Starts execution and consensus nodes.')
def node_start(data_dir: Path, network: str) -> None:
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt=LOG_DATE_FORMAT,
        level='INFO',
    )
    # Create the data directory if it does not exist
    # Also the data directory could be created by the `init` command
    data_dir.mkdir(parents=True, exist_ok=True)

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
