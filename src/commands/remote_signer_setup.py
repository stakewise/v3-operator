import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import aiohttp
import click
import milagro_bls_binding as bls
from aiohttp import ClientTimeout
from eth_typing import BLSPrivateKey, HexAddress
from web3 import Web3

from src.common.credentials import Credential
from src.common.execution import get_oracles
from src.common.password import get_or_create_password_file
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import REMOTE_SIGNER_TIMEOUT, settings
from src.validators.signing.key_shares import private_key_to_private_key_shares
from src.validators.signing.remote import RemoteSignerConfiguration
from src.validators.utils import load_keystores


@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
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
    '--remove-existing-keys',
    type=bool,
    is_flag=True,
    help='Whether to remove existing keys from the remote signer. Useful'
    ' when the oracle set changes and the previously generated key shares'
    ' are no longer going to be used.',
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
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.command(help='Generates and uploads private key shares to a remote signer.')
# pylint: disable-next=too-many-arguments
def remote_signer_setup(
    vault: HexAddress,
    remote_signer_url: str,
    remove_existing_keys: bool,
    data_dir: str,
    keystores_dir: str | None,
    execution_endpoints: str,
    verbose: bool,
) -> None:
    config = VaultConfig(vault, Path(data_dir))
    config.load()
    settings.set(
        vault=vault,
        vault_dir=config.vault_dir,
        network=config.network,
        execution_endpoints=execution_endpoints,
        keystores_dir=keystores_dir,
        remote_signer_url=remote_signer_url,
        verbose=verbose,
    )

    try:
        # Try-catch to enable async calls in test - an event loop
        #  will already be running in that case
        try:
            asyncio.get_running_loop()
            # we need to create a separate thread so we can block before returning
            with ThreadPoolExecutor(1) as pool:
                pool.submit(
                    lambda: asyncio.run(main(remove_existing_keys=remove_existing_keys))
                ).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(main(remove_existing_keys=remove_existing_keys))
            else:
                raise e
    except Exception as e:
        log_verbose(e)


# pylint: disable-next=too-many-locals
async def main(remove_existing_keys: bool) -> None:
    keystores = load_keystores()

    if len(keystores) == 0:
        raise click.ClickException('Keystores not found.')

    # Check if remote signer's keymanager API is reachable before taking further steps
    async with aiohttp.ClientSession(
        timeout=ClientTimeout(connect=REMOTE_SIGNER_TIMEOUT)
    ) as session:
        resp = await session.get(f'{settings.remote_signer_url}/eth/v1/keystores')
        if resp.status != 200:
            raise RuntimeError(f'Failed to connect to remote signer, returned {await resp.text()}')

    oracles = await get_oracles()

    try:
        remote_signer_config = RemoteSignerConfiguration.from_file(
            settings.remote_signer_config_file
        )
    except FileNotFoundError:
        remote_signer_config = RemoteSignerConfiguration(pubkeys_to_shares={})

    credentials = []
    for pubkey, private_key in keystores.items():  # pylint: disable=no-member
        private_key_shares = private_key_to_private_key_shares(
            private_key=private_key,
            threshold=oracles.exit_signature_recover_threshold,
            total=len(oracles.public_keys),
        )

        for idx, private_key_share in enumerate(private_key_shares):
            credentials.append(
                Credential(
                    private_key=BLSPrivateKey(int.from_bytes(private_key_share, 'big')),
                    path=f'share_{pubkey}_{idx}',
                    network=settings.network,
                    vault=settings.vault,
                )
            )
        remote_signer_config.pubkeys_to_shares[pubkey] = [
            Web3.to_hex(bls.SkToPk(priv_key)) for priv_key in private_key_shares
        ]

    click.echo(
        f'Successfully generated {len(credentials)} key shares'
        f' for {len(keystores)} private key(s)!',
    )

    # Import as keystores to remote signer
    password = get_or_create_password_file(settings.keystores_password_file)
    key_share_keystores = []
    for credential in credentials:
        key_share_keystores.append(deepcopy(credential.encrypt_signing_keystore(password=password)))

    async with aiohttp.ClientSession(
        timeout=ClientTimeout(connect=REMOTE_SIGNER_TIMEOUT)
    ) as session:
        data = {
            'keystores': [ksk.as_json() for ksk in key_share_keystores],
            'passwords': [password for _ in key_share_keystores],
        }
        resp = await session.post(f'{settings.remote_signer_url}/eth/v1/keystores', json=data)
        if resp.status != 200:
            raise RuntimeError(
                f'Error occurred during import of keystores to remote signer'
                f' - status code {resp.status}, body: {await resp.text()}'
            )

    click.echo(
        f'Successfully imported {len(key_share_keystores)} key shares into remote signer.',
    )

    # Remove local keystores - keys are loaded in remote signer and are not
    # needed locally anymore
    for keystore_file in os.listdir(settings.keystores_dir):
        os.remove(settings.keystores_dir / keystore_file)

    click.echo('Removed keystores from local filesystem.')

    # Remove outdated keystores from remote signer
    if remove_existing_keys:
        active_pubkey_shares = {
            pk for pk_list in remote_signer_config.pubkeys_to_shares.values() for pk in pk_list
        }

        async with aiohttp.ClientSession(
            timeout=ClientTimeout(connect=REMOTE_SIGNER_TIMEOUT)
        ) as session:
            resp = await session.get(f'{settings.remote_signer_url}/eth/v1/keystores')
            pubkeys_data = (await resp.json())['data']
            pubkeys_remote_signer = {
                pubkey_dict.get('validating_pubkey') for pubkey_dict in pubkeys_data
            }

            # Only remove pubkeys from signer that are no longer needed
            inactive_pubkeys = pubkeys_remote_signer - active_pubkey_shares

            resp = await session.delete(
                f'{settings.remote_signer_url}/eth/v1/keystores',
                json={'pubkeys': list(inactive_pubkeys)},
            )
            if resp.status != 200:
                raise RuntimeError(
                    f'Error occurred while deleting existing keys from remote signer'
                    f' - status code {resp.status}, body: {await resp.text()}'
                )

            click.echo(
                f'Removed {len(inactive_pubkeys)} keys from remote signer',
            )

    remote_signer_config.save(settings.remote_signer_config_file)

    click.echo(
        f'Done.'
        f' Successfully configured operator to use remote signer'
        f' for {len(keystores)} public key(s)!',
    )
