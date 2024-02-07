import asyncio
import logging
import os
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import aiohttp
import click
from aiohttp import ClientTimeout
from eth_typing import HexAddress

from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import chunkify, log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import (
    REMOTE_SIGNER_TIMEOUT,
    REMOTE_SIGNER_UPLOAD_CHUNK_SIZE,
    settings,
)
from src.validators.keystores.local import LocalKeystore

logger = logging.getLogger(__name__)


@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    envvar='VAULT',
    callback=validate_eth_address,
)
@click.option(
    '--remote-signer-url',
    type=str,
    envvar='REMOTE_SIGNER_URL',
    required=True,
    help='The base URL of the remote signer, e.g. http://signer:9000',
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(file_okay=False, dir_okay=True),
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
@click.option(
    '--log-level',
    type=click.Choice(
        LOG_LEVELS,
        case_sensitive=False,
    ),
    default='INFO',
    envvar='LOG_LEVEL',
    help='The log level.',
)
@click.command(help='Uploads private keys to a remote signer.')
# pylint: disable-next=too-many-arguments
def remote_signer_setup(
    vault: HexAddress,
    remote_signer_url: str,
    data_dir: str,
    keystores_dir: str | None,
    verbose: bool,
    log_level: str,
) -> None:
    config = VaultConfig(vault, Path(data_dir))
    config.load()
    settings.set(
        vault=vault,
        vault_dir=config.vault_dir,
        network=config.network,
        keystores_dir=keystores_dir,
        remote_signer_url=remote_signer_url,
        verbose=verbose,
        log_level=log_level,
    )

    try:
        # Try-catch to enable async calls in test - an event loop
        #  will already be running in that case
        try:
            asyncio.get_running_loop()
            # we need to create a separate thread so we can block before returning
            with ThreadPoolExecutor(1) as pool:
                pool.submit(lambda: asyncio.run(main())).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(main())
            else:
                raise e
    except Exception as e:
        log_verbose(e)


async def main() -> None:
    setup_logging()
    keystore_files = LocalKeystore.list_keystore_files()
    if len(keystore_files) == 0:
        raise click.ClickException('Keystores not found.')

    # Check if remote signer's keymanager API is reachable before taking further steps
    async with aiohttp.ClientSession(timeout=ClientTimeout(REMOTE_SIGNER_TIMEOUT)) as session:
        resp = await session.get(f'{settings.remote_signer_url}/eth/v1/keystores')
        if resp.status == 404:
            logger.warning(
                'make sure that you run remote signer with '
                '`--enable-key-manager-api=true` option'
            )
        if resp.status != 200:
            raise RuntimeError(f'Failed to connect to remote signer, returned {await resp.text()}')

    # Read keystores without decrypting
    keystores_json = []
    for keystore_file in keystore_files:
        with open(settings.keystores_dir / keystore_file.name, encoding='ascii') as f:
            keystores_json.append(f.read())

    # Import keystores to remote signer
    chunk_size = REMOTE_SIGNER_UPLOAD_CHUNK_SIZE

    async with aiohttp.ClientSession(timeout=ClientTimeout(REMOTE_SIGNER_TIMEOUT)) as session:
        for keystores_json_chunk, keystore_files_chunk in zip(
            chunkify(keystores_json, chunk_size), chunkify(keystore_files, chunk_size)
        ):
            data = {
                'keystores': keystores_json_chunk,
                'passwords': [kf.password for kf in keystore_files_chunk],
            }
            upload_url = f'{settings.remote_signer_url}/eth/v1/keystores'
            logger.debug('POST %s', upload_url)
            resp = await session.post(upload_url, json=data)
            if resp.status != 200:
                raise RuntimeError(
                    f'Error occurred during import of keystores to remote signer'
                    f' - status code {resp.status}, body: {await resp.text()}'
                )

    click.echo(
        f'Successfully imported {len(keystore_files)} keys into remote signer.',
    )

    # Keys are loaded in remote signer and are not needed locally anymore
    if click.confirm('Remove local keystores?'):
        shutil.rmtree(settings.keystores_dir)

        if settings.keystores_password_dir.exists():
            shutil.rmtree(settings.keystores_password_dir)

        if settings.keystores_password_file.exists():
            os.remove(settings.keystores_password_file)

        click.echo('Removed keystores from local filesystem.')

    click.echo(
        f'Done.'
        f' Successfully configured operator to use remote signer'
        f' for {len(keystore_files)} public key(s)!',
    )
