import logging
import time
from pathlib import Path

import click

from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import DEFAULT_NETWORK, LOG_DATE_FORMAT
from src.nodes.process import LighthouseProcess, RethProcess, shutdown_processes

logger = logging.getLogger(__name__)


@click.option(
    '--data-dir',
    default=Path.home() / '.stakewise',
    envvar='DATA_DIR',
    help='Path where the nodes data will be placed',
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
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

    reth_process = RethProcess(network=network, data_dir=data_dir)
    lighthouse_process = LighthouseProcess(network=network, data_dir=data_dir)

    reth_process.start()
    lighthouse_process.start()

    try:
        while True:
            # todo: what to do if processes are not alive?
            if not reth_process.is_alive:
                click.echo(f'{reth_process.name} is terminated')
                break

            if not lighthouse_process.is_alive:
                click.echo(f'{lighthouse_process.name} is terminated')
                break

            time.sleep(1)
    finally:
        # We get here in the case of Ctrl+C
        # Shut down the processes gracefully
        click.echo('Shutting down nodes...')
        shutdown_processes([reth_process, lighthouse_process])
