import asyncio
import logging
from pathlib import Path

import click
import psutil
from web3 import Web3

from src.common.clients import setup_clients
from src.common.validators import validate_eth_address
from src.config.networks import AVAILABLE_NETWORKS, NETWORKS
from src.config.settings import DEFAULT_NETWORK, LOG_DATE_FORMAT, settings
from src.nodes.exceptions import NodeFailedToStartError
from src.nodes.lighthouse import generate_validator_definitions_file
from src.nodes.process import (
    LighthouseProcessBuilder,
    LighthouseVCProcessBuilder,
    ProcessRunner,
    RethProcessBuilder,
)
from src.nodes.typings import StdStreams
from src.validators.keystores.local import LocalKeystore

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
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault addresses',
    type=str,
    callback=validate_eth_address,
)
@click.option('--show-reth-output', is_flag=True, default=False, help='Whether to show Reth output')
@click.option(
    '--show-lighthouse-output',
    is_flag=True,
    default=False,
    help='Whether to show Lighthouse output',
)
@click.option(
    '--show-validator-output',
    is_flag=True,
    default=False,
    help='Whether to show validator client output',
)
@click.command(help='Starts execution and consensus nodes, starts validator client.')
# pylint: disable=too-many-arguments
def node_start(
    data_dir: Path,
    network: str,
    no_confirm: bool,
    vault: str,
    show_reth_output: bool,
    show_lighthouse_output: bool,
    show_validator_output: bool,
) -> None:
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt=LOG_DATE_FORMAT,
        level='INFO',
    )

    # Minimal settings for the nodes
    settings.set(
        vaults=[Web3.to_checksum_address(vault)],
        network=network,
        data_dir=data_dir / network,
    )

    click.echo('Checking hardware requirements...')
    _check_hardware_requirements(data_dir=data_dir, network=network, no_confirm=no_confirm)

    validator_definitions_path = (
        settings.nodes_dir / 'lighthouse' / 'validators' / 'validator_definitions.yml'
    )

    click.echo('Generating validator definitions file...')
    generate_validator_definitions_file(
        keystores_dir=settings.keystores_dir,
        keystore_files=LocalKeystore.list_keystore_files(),
        output_path=validator_definitions_path,
    )
    asyncio.run(
        main(
            data_dir=data_dir,
            network=network,
            show_reth_output=show_reth_output,
            show_lighthouse_output=show_lighthouse_output,
            show_validator_output=show_validator_output,
        )
    )


async def main(
    data_dir: Path,
    network: str,
    show_reth_output: bool,
    show_lighthouse_output: bool,
    show_validator_output: bool,
) -> None:
    await setup_clients()

    reth_process_builder = RethProcessBuilder(
        network=network, data_dir=data_dir, streams=_build_std_streams(show_reth_output)
    )
    lighthouse_process_builder = LighthouseProcessBuilder(
        network=network, data_dir=data_dir, streams=_build_std_streams(show_lighthouse_output)
    )

    lighthouse_vc_process_builder = LighthouseVCProcessBuilder(
        network=network,
        data_dir=data_dir,
        vault_address=settings.vaults[0],
        streams=_build_std_streams(show_validator_output),
    )

    min_restart_interval = 60  # seconds

    # Create process runners
    reth_runner = ProcessRunner(
        process_builder=reth_process_builder,
        min_restart_interval=min_restart_interval,
    )
    lighthouse_runner = ProcessRunner(
        process_builder=lighthouse_process_builder,
        min_restart_interval=min_restart_interval,
    )
    lighthouse_vc_runner = ProcessRunner(
        process_builder=lighthouse_vc_process_builder,
        min_restart_interval=min_restart_interval,
    )

    try:
        await asyncio.gather(
            reth_runner.run(),
            lighthouse_runner.run(),
            lighthouse_vc_runner.run(),
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
