import asyncio
import logging
import sys
from os import makedirs, path
from pathlib import Path

import click
from eth_typing import HexStr
from eth_utils import add_0x_prefix
from staking_deposit.key_handling.keystore import ScryptKeystore

from src.common.utils import log_verbose
from src.config.config import OperatorConfig
from src.config.settings import settings
from src.validators.exceptions import KeystoreException
from src.validators.keystores.local import KeystoreFile, LocalKeystore

logger = logging.getLogger(__name__)


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--keystores-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='KEYSTORES_DIR',
    help='Absolute path to the directory with all the encrypted keystores. '
    'Default is the directory generated with "create-keys" command.',
)
@click.command(
    help='Fetch available public keys from local keystores and export them to validators.txt.'
)
# pylint: disable-next=too-many-arguments
def generate_public_keys(
    verbose: bool,
    data_dir: str,
    keystores_dir: str | None,
) -> None:
    operator_config = OperatorConfig(Path(data_dir))
    operator_config.load()
    network = operator_config.network

    settings.set(
        vaults=[],
        config_dir=operator_config.config_dir,
        verbose=verbose,
        network=network,
        keystores_dir=keystores_dir,
    )

    try:
        asyncio.run(main())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main() -> None:
    keystore_files = LocalKeystore.list_keystore_files()
    logger.info('Loading keystores from %s...', settings.keystores_dir)
    keys = [
        _process_keystore_file(keystore_file, settings.keystores_dir)
        for keystore_file in keystore_files
    ]
    keys.sort(key=lambda x: x[0])
    _export_validators_keys(public_keys=[x[1] for x in keys])
    logger.info('Saved %d public keys to validators.txt', len(keys))


def _process_keystore_file(keystore_file: KeystoreFile, keystore_path: Path) -> tuple[int, HexStr]:
    file_name = keystore_file.name
    file_path = keystore_path / file_name
    try:
        keystore = ScryptKeystore.from_file(file_path)
        index = keystore.path.split('/')[-3]
        return int(index), add_0x_prefix(HexStr(keystore.pubkey))
    except BaseException as e:
        raise KeystoreException(f'Invalid keystore format in file "{file_name}"') from e


def _export_validators_keys(public_keys: list[HexStr]) -> None:
    filename = settings.config_dir / 'validators.txt'
    if filename.exists():
        click.confirm(
            'Remove existing validators.txt file?',
            default=True,
            abort=True,
        )

    makedirs(path.dirname(path.abspath(filename)), exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        for public_key in public_keys:
            f.write(f'{public_key}\n')
