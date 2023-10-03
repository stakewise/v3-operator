import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

import aiohttp
import click
import milagro_bls_binding as bls
from eth_typing import BLSPrivateKey, HexAddress
from py_ecc.bls import G2ProofOfPossession
from staking_deposit.key_handling.keystore import ScryptKeystore
from web3 import Web3

from src.common.contrib import bytes_to_str
from src.common.credentials import Credential
from src.common.execution import get_oracles
from src.common.password import get_or_create_password_file
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import settings
from src.key_manager.database import Database, check_db_connection
from src.key_manager.encryptor import Encryptor
from src.key_manager.typings import DatabaseConfigRecord, DatabaseKeyRecord
from src.validators.signing.key_shares import private_key_to_private_key_shares
from src.validators.signing.remote import RemoteSignerConfiguration
from src.validators.utils import list_keystore_files, load_keystores


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
    '--remote-db-url',
    help='When provided will upload encrypted keystores to the Postgres DB. '
    'The new encryption key will be generated if `db-encrypt-key` is not provided. '
    'For example, postgresql://username:pass@hostname/dbname.',
    prompt=False,
    required=False,
)
@click.option(
    '--remote-db-key',
    help='The key for encrypting database record. '
    'If you upload new keystores use the same encryption key.',
    required=False,
    prompt=False,
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
    remote_db_url: str | None = None,
    remote_db_key: str | None = None,
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
                    lambda: asyncio.run(
                        main(
                            remove_existing_keys=remove_existing_keys,
                            remote_db_url=remote_db_url,
                            remote_db_key=remote_db_key,
                        )
                    )
                ).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(
                    main(
                        remove_existing_keys=remove_existing_keys,
                        remote_db_url=remote_db_url,
                        remote_db_key=remote_db_key,
                    )
                )
            else:
                raise e
    except Exception as e:
        log_verbose(e)


# pylint: disable-next=too-many-locals,too-many-branches
async def main(
    remove_existing_keys: bool,
    remote_db_url: str | None,
    remote_db_key: str | None,
) -> None:
    keystores = load_keystores()

    if len(keystores) == 0:
        raise click.ClickException('Keystores not found.')

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

    if not credentials:
        click.echo('Credentials list is empty')

    click.echo(
        f'Successfully generated {len(credentials)} key shares'
        f' for {len(keystores)} private key(s)!',
    )

    # Import as keystores to remote signer
    password = get_or_create_password_file(str(settings.keystores_password_file))
    key_share_keystores = []
    for credential in credentials:
        key_share_keystores.append(deepcopy(credential.encrypt_signing_keystore(password=password)))

    key_shares = {
        'keystores': [ksk.as_json() for ksk in key_share_keystores],
        'passwords': [password for _ in key_share_keystores],
    }

    if remote_db_url:
        _update_db(remote_db_url=remote_db_url, remote_db_key=remote_db_key, key_shares=key_shares)
    else:
        async with aiohttp.ClientSession() as session:
            resp = await session.post(
                f'{settings.remote_signer_url}/eth/v1/keystores', json=key_shares
            )
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
        if remote_db_url:
            database = Database(
                db_url=str(remote_db_url),
            )
            all_db_public_keys = set(database.fetch_all_public_keys())
            inactive_pubkeys = all_db_public_keys - active_pubkey_shares
            database.delete_keys_by_public_key(list(inactive_pubkeys))
            click.echo(
                f'Removed {len(inactive_pubkeys)} keys from remote database',
            )
        else:
            async with aiohttp.ClientSession() as session:
                resp = await session.get(f'{settings.remote_signer_url}/api/v1/eth2/publicKeys')
                pubkeys_remote_signer = set(await resp.json())

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


# pylint: disable-next=too-many-locals
def _update_db(
    remote_db_url: str | None,
    remote_db_key: str | None,
    key_shares: dict | None,
) -> None:
    check_db_connection(remote_db_url)

    keystores_password = get_or_create_password_file(str(settings.keystores_password_file))

    private_keys = []

    with click.progressbar(
        list_keystore_files(),
        label='Loading keystores...\t\t',
        show_percent=False,
        show_pos=True,
    ) as _keystore_files:
        for filename in _keystore_files:
            try:
                keystore = ScryptKeystore.from_file(filename).decrypt(keystores_password)
                private_keys.append(int.from_bytes(keystore, 'big'))
            except (json.JSONDecodeError, KeyError) as e:
                click.secho(
                    f'Failed to load keystore {filename}. Error: {str(e)}.',
                    fg='red',
                )

    with click.progressbar(
        length=len(key_shares['keystores']),  # type: ignore
        label='Loading key shares...\t\t',
        show_percent=False,
        show_pos=True,
    ) as progressbar:
        for index, key_share_str in enumerate(key_shares['keystores']):  # type: ignore
            try:
                keystore_password = key_shares['passwords'][index]  # type: ignore
                # Parse key_share from string to dictionary
                key_share = json.loads(key_share_str)
                keystore = ScryptKeystore.from_json(key_share).decrypt(keystore_password)
                private_keys.append(int.from_bytes(keystore, 'big'))
            except (json.JSONDecodeError, KeyError) as e:
                click.secho(
                    f'Failed to load keystore {key_share_str}. Error: {str(e)}.',
                    fg='red',
                )
            progressbar.update(1)

    database = Database(
        db_url=str(remote_db_url),
    )
    encryptor = Encryptor(remote_db_key)

    database_records = _encrypt_private_keys(
        private_keys=private_keys,
        encryptor=encryptor,
    )
    database.upload_keys(keys=database_records)
    total_keys_count = database.fetch_public_keys_count()

    configs = [
        _read_config_file_to_record(
            settings.remote_signer_config_file, 'remote_signer_config.json'
        ),
        _read_config_file_to_record(settings.deposit_data_file, 'deposit_data.json'),
    ]
    database.upload_configs(configs)

    click.clear()

    click.secho(
        f'The database contains {total_keys_count} validator keys.\n'
        f"The decryption key: '{encryptor.str_key}'\n"
        'The configuration files have been uploaded to the remote database.',
        bold=True,
        fg='green',
    )


def _read_config_file_to_record(filepath: Path, filename: str) -> DatabaseConfigRecord:
    """Reads a JSON config file and returns a DatabaseConfigRecord instance."""
    with open(filepath, encoding='utf-8') as file:
        data = json.dumps(json.load(file))
    return DatabaseConfigRecord(name=filename, data=data)


def _encrypt_private_keys(private_keys: list[int], encryptor: Encryptor) -> list[DatabaseKeyRecord]:
    """
    Returns prepared database key records from the private keys.
    """

    click.secho('Encrypting database keys...', bold=True)
    key_records: list[DatabaseKeyRecord] = []
    for private_key in private_keys:
        encrypted_private_key, nonce = encryptor.encrypt(str(private_key))

        key_record = DatabaseKeyRecord(
            public_key=Web3.to_hex(G2ProofOfPossession.SkToPk(private_key)),
            private_key=bytes_to_str(encrypted_private_key),
            nonce=bytes_to_str(nonce),
        )

        if key_record not in key_records:
            key_records.append(key_record)

    return key_records
