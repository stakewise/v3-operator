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

    process_builder = ProcessBuilder(network=network, data_dir=data_dir)
    reth_process = process_builder.get_reth_process()
    lighthouse_process = process_builder.get_lighthouse_process()

    reth_process.start()
    lighthouse_process.start()

    try:
        while True:
            # Keep the processes alive
            if not reth_process.is_alive:
                click.echo(f'{reth_process.name} is terminated. Restarting...')
                reth_process = process_builder.get_reth_process()
                reth_process.start()

            if not lighthouse_process.is_alive:
                click.echo(f'{lighthouse_process.name} is terminated. Restarting...')
                lighthouse_process = process_builder.get_lighthouse_process()
                lighthouse_process.start()

            time.sleep(1)
    except KeyboardInterrupt:
        # Handle Ctrl+C
        # Shut down the processes gracefully
        # Do not reraise
        click.echo('Shutting down nodes...')
        shutdown_processes([reth_process, lighthouse_process])
    finally:
        # Handle unexpected error
        # Shut down the processes gracefully
        # Reraise the exception
        if reth_process.is_alive or lighthouse_process.is_alive:
            click.echo('Shutting down nodes...')
            shutdown_processes([reth_process, lighthouse_process])


class ProcessBuilder:
    def __init__(self, network: str, data_dir: Path):
        self.network = network
        self.data_dir = data_dir

    @property
    def nodes_dir(self) -> Path:
        return self.data_dir / self.network / 'nodes'

    def get_reth_process(self) -> RethProcess:
        reth_dir = self.nodes_dir / 'reth'

        return RethProcess(network=self.network, reth_dir=reth_dir)

    def get_lighthouse_process(self) -> LighthouseProcess:
        lighthouse_dir = self.nodes_dir / 'lighthouse'

        # Let Reth create the JWT secret file on first run
        jwt_secret_path = self.get_default_jwt_secret_path()

        return LighthouseProcess(
            network=self.network, lighthouse_dir=lighthouse_dir, jwt_secret_path=jwt_secret_path
        )

    def get_default_jwt_secret_path(self) -> Path:
        """Returns the default JWT secret path for Reth."""
        return self.nodes_dir / 'reth' / 'jwt.hex'
