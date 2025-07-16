import logging
import time
from pathlib import Path

import click

from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import DEFAULT_NETWORK, LOG_DATE_FORMAT
from src.nodes.process import RethProcess


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
@click.command(
    help='Starts execution node and consensus node.',
)
def node_start(data_dir: Path, network: str) -> None:
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt=LOG_DATE_FORMAT,
        level='INFO',
    )

    reth_process = RethProcess(network=network, data_dir=data_dir)

    reth_process.start()
    try:
        # Wait for keyboard interrupt to stop the process
        while True:
            if not reth_process.is_alive:
                click.echo(f'{reth_process.name} is terminated')
                break

            time.sleep(1)
    finally:
        if reth_process.is_alive:
            click.echo(f'Stopping {reth_process.name}')
            reth_process.stop()
