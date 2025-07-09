import io
import os
import tarfile
from os import makedirs
from pathlib import Path

import click
import requests

from src.common.utils import greenify
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import DEFAULT_NETWORK
from src.nodes.typings import Release

REQUESTS_TIMEOUT = 60


@click.option(
    '--data-dir',
    default=Path.home() / '.stakewise',
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
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
@click.command(help='Creates the validator keys from the mnemonic.')
def node_install(data_dir: Path, network: str) -> None:
    """
    Installs the node software.
    """
    # Define the path to the nodes installation directories
    nodes_dir = data_dir / network / 'nodes'
    reth_dir = nodes_dir / 'reth'
    lighthouse_dir = nodes_dir / 'lighthouse'

    # Create the directories if they do not exist
    makedirs(reth_dir, exist_ok=True)
    makedirs(lighthouse_dir, exist_ok=True)

    # Installing Reth and Lighthouse binaries
    install_reth_binary(reth_dir)
    install_lighthouse_binary(lighthouse_dir)


def install_reth_binary(dir_to_install: Path) -> None:
    """
    Installs the Reth binary.
    """
    repo_url = 'https://github.com/paradigmxyz/reth'
    app_version = 'v1.5.1'

    release = Release(
        repo_url=repo_url,
        app_version=app_version,
    )
    install_binary_release(
        release=release,
        dir_to_install=dir_to_install,
    )

    click.echo(greenify('Reth installation completed successfully.'))


def install_lighthouse_binary(dir_to_install: Path) -> None:
    """
    Installs the Lighthouse binary.
    """
    repo_url = 'https://github.com/sigp/lighthouse'
    app_version = 'v7.0.1'

    release = Release(
        repo_url=repo_url,
        app_version=app_version,
    )
    install_binary_release(
        release=release,
        dir_to_install=dir_to_install,
    )
    click.echo(greenify('Lighthouse installation completed successfully.'))


def install_binary_release(release: Release, dir_to_install: Path) -> None:
    # Download the binary
    click.echo(f'Downloading Lighthouse binary from {release.binary_url}...')
    response = requests.get(release.binary_url, timeout=REQUESTS_TIMEOUT)
    response.raise_for_status()
    response_len_mb = round(len(response.content) / 1024 / 1024, 1)
    click.echo(f'Download complete. {response_len_mb} MB. Extracting...')

    # Extract the binary from tar.gz
    # Extract only targeted file because of security reasons
    # Normally the archive contains only one file, but we check it anyway
    with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tar:
        members = [m for m in tar.getmembers() if m.name == release.binary_name]
        if not members:
            raise click.ClickException(f'Binary {release.binary_name} not found in the archive.')
        tar.extractall(path=dir_to_install, members=members)  # nosec

    # Check permissions of the extracted binary
    binary_path = dir_to_install / release.binary_name
    ensure_executable_permissions(binary_path)


def ensure_executable_permissions(binary_path: Path) -> None:
    """
    Ensures that the binary has executable permissions.
    This is necessary for POSIX systems (Linux, macOS) to run the binary.
    """
    if os.name != 'posix':
        return

    # Get permissions of the binary
    is_executable = os.access(binary_path, os.X_OK)

    if not is_executable:
        raise click.ClickException(
            f'Binary is not executable: {binary_path}. Please check permissions.'
        )
