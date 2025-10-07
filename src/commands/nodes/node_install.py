import io
import os
import platform
import tarfile
from os import makedirs
from pathlib import Path

import click
import requests

from src.common.utils import greenify
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import DEFAULT_NETWORK, settings
from src.nodes.typings import Release

DEFAULT_REQUESTS_TIMEOUT = 60

DEFAULT_RETH_VERSION = 'v1.5.1'
DEFAULT_LIGHTHOUSE_VERSION = 'v7.1.0'


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
    help='The network of your vault.',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.option(
    '--reth-version',
    default=DEFAULT_RETH_VERSION,
    help='Version of the Reth binary to install.',
    type=str,
    show_default=True,
)
@click.option(
    '--lighthouse-version',
    default=DEFAULT_LIGHTHOUSE_VERSION,
    envvar='LIGHTHOUSE_VERSION',
    help='Version of the Lighthouse binary to install.',
    type=str,
    show_default=True,
)
@click.command(
    help='Installs execution node and consensus node to the data dir.',
)
def node_install(data_dir: Path, network: str, reth_version: str, lighthouse_version: str) -> None:
    """
    Downloads and unpacks pre-built binaries for both execution and consensus nodes.
    """
    # Using zero address since vault directory is not required for this command
    vault_address = ZERO_CHECKSUM_ADDRESS

    # Minimal settings for the nodes
    settings.set(
        vault=vault_address,
        network=network,
        vault_dir=data_dir / vault_address,
        nodes_dir=data_dir / network / 'nodes',
    )

    # Define the path to the nodes installation directories
    reth_dir = settings.nodes_dir / 'reth'
    lighthouse_dir = settings.nodes_dir / 'lighthouse'

    # Create the directories if they do not exist
    makedirs(reth_dir, exist_ok=True)
    makedirs(lighthouse_dir, exist_ok=True)

    # Installing Reth and Lighthouse binaries
    install_reth_binary(reth_dir, app_version=reth_version)
    install_lighthouse_binary(lighthouse_dir, app_version=lighthouse_version)


def install_reth_binary(dir_to_install: Path, app_version: str) -> None:
    """
    Installs the Reth binary.
    """
    repo_url = 'https://github.com/paradigmxyz/reth'

    release = Release(
        repo_url=repo_url,
        app_version=app_version,
    )
    install_binary_release(
        release=release,
        dir_to_install=dir_to_install,
    )

    click.echo(
        greenify(
            f'{release.app_name.capitalize()} {app_version} installation completed successfully.'
        )
    )


def install_lighthouse_binary(dir_to_install: Path, app_version: str) -> None:
    """
    Installs the Lighthouse binary.
    """
    repo_url = 'https://github.com/sigp/lighthouse'

    release = Release(
        repo_url=repo_url,
        app_version=app_version,
    )
    install_binary_release(
        release=release,
        dir_to_install=dir_to_install,
    )
    click.echo(
        greenify(
            f'{release.app_name.capitalize()} {app_version} installation completed successfully.'
        )
    )


def install_binary_release(release: Release, dir_to_install: Path) -> None:
    # Get environment details
    os_name = platform.system()
    arch = platform.machine()

    binary_url = release.get_binary_url(os_name=os_name, arch=arch)
    click.echo(f'Downloading {release.app_name.capitalize()} binary from {binary_url}...')

    # Download the binary, displaying a progress bar
    content = download_binary_with_progress(binary_url)
    response_len_mb = round(len(content) / 1024 / 1024, 1)
    click.echo(f'Download complete. {response_len_mb} MB. Extracting to {dir_to_install}...')

    # Extract the binary from tar.gz
    # Extract only targeted file because of security reasons
    # Normally the archive contains only one file, but we check it anyway
    binary_name = release.get_binary_name(os_name)
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as tar:
        members = [m for m in tar.getmembers() if m.name == binary_name]
        if not members:
            raise click.ClickException(f'Binary {binary_name} not found in the archive.')
        tar.extractall(path=dir_to_install, members=members)  # nosec

    # Check permissions of the extracted binary
    binary_path = dir_to_install / binary_name
    ensure_executable_permissions(binary_path)


def download_binary_with_progress(url: str) -> bytes:
    """
    Downloads a binary file from the given URL and returns its content.
    Displays a progress bar during the download.
    """
    with requests.get(url, timeout=DEFAULT_REQUESTS_TIMEOUT, stream=True) as response:
        response.raise_for_status()
        total = int(response.headers.get('content-length', 0))
        chunks = []
        with click.progressbar(
            length=total, label='Downloading', show_percent=True, show_eta=True
        ) as bar:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    chunks.append(chunk)
                    bar.update(len(chunk))

    return b''.join(chunks)


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
        click.echo(
            f'The binary {binary_path} is not executable. '
            f'Attempting to set executable permissions...'
        )
        try:
            # Set executable permissions
            os.chmod(binary_path, 0o755)  # nosec
        except Exception as e:
            raise click.ClickException(f'Failed to set executable permissions: {e}')
