import asyncio
import logging
import sys
from os import makedirs, path
from pathlib import Path

import click
from eth_typing import HexStr

from src.common.logging import setup_logging
from src.common.utils import log_verbose
from src.config.config import OperatorConfig
from src.config.settings import PUBLIC_KEYS_FILENAME, settings
from src.validators.keystores.local import LocalKeystore

logger = logging.getLogger(__name__)


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the keystores and config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--keystores-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='KEYSTORES_DIR',
    help='Absolute path to the directory with all the encrypted keystores. '
    'Default is the directory generated with "create-keys" command.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.command(
    help='Fetch available public keys from local keystores and export them to validators.txt.'
)
# pylint: disable-next=too-many-arguments
def export_public_keys(
    data_dir: str,
    keystores_dir: str | None,
    verbose: bool,
) -> None:
    setup_logging()
    operator_config = OperatorConfig(Path(data_dir))
    operator_config.load()
    network = operator_config.network

    settings.set(
        vaults=[],
        network=network,
        data_dir=operator_config.data_dir,
        keystores_dir=keystores_dir,
        verbose=verbose,
    )

    try:
        asyncio.run(main())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main() -> None:
    logger.info('Loading keystores from %s...', settings.keystores_dir)
    public_keys = LocalKeystore.get_public_keys_from_keystore_files()
    _export_public_keys(public_keys)
    logger.info('Saved %d public keys to validators.txt', len(public_keys))


def _export_public_keys(public_keys: list[HexStr]) -> None:
    filename = settings.data_dir / PUBLIC_KEYS_FILENAME
    if filename.exists():
        click.confirm(
            f'Remove existing {PUBLIC_KEYS_FILENAME} file?',
            default=True,
            abort=True,
        )

    makedirs(path.dirname(path.abspath(filename)), exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        for public_key in public_keys:
            f.write(f'{public_key}\n')
