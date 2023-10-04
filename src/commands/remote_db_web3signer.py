import glob
import os
from os import mkdir
from os.path import exists
from typing import List

import click
import yaml
from eth_utils import add_0x_prefix
from web3 import Web3
from web3.types import HexStr

from src.common.contrib import is_lists_equal
from src.common.validators import validate_db_uri, validate_env_name
from src.key_manager.database import Database, check_db_connection
from src.key_manager.encryptor import Encryptor

DECRYPTION_KEY_ENV = 'DECRYPTION_KEY'


@click.option(
    '--db-url',
    help='The database connection address.',
    prompt="Enter the database connection string, ex. 'postgresql://username:pass@hostname/dbname'",
    callback=validate_db_uri,
)
@click.option(
    '--output-dir',
    help='The folder where web3signer keystores will be saved.',
    prompt='Enter the folder where web3signer keystores will be saved',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.option(
    '--decryption-key-env',
    help='The environment variable with the decryption key for private keys in the database.',
    default=DECRYPTION_KEY_ENV,
    callback=validate_env_name,
)
@click.command(help='Synchronizes web3signer private keys from the database')
# pylint: disable-next=too-many-locals
def remote_db_web3signer(db_url: str, output_dir: str, decryption_key_env: str) -> None:
    """
    The command is running by the init container in web3signer pods.
    Fetch and decrypt keys for web3signer and store them as keypairs in the output_dir.
    """
    check_db_connection(db_url)

    database = Database(db_url=db_url)
    keys_records = database.fetch_keys()

    # decrypt private keys
    decryption_key = os.environ[decryption_key_env]
    decryptor = Encryptor(decryption_key)
    private_keys: List[str] = []
    for key_record in keys_records:
        key = decryptor.decrypt(data=key_record.private_key, nonce=key_record.nonce)
        key_hex = Web3.to_hex(int(key))
        # pylint: disable-next=unsubscriptable-object
        key_hex = HexStr(key_hex[2:].zfill(64))  # pad missing leading zeros
        private_keys.append(add_0x_prefix(key_hex))

    if not exists(output_dir):
        mkdir(output_dir)

    # check current keys
    current_keys = []
    for filename in glob.glob(os.path.join(output_dir, '*.yaml')):
        with open(filename, 'r', encoding='utf-8') as f:
            content = yaml.safe_load(f.read())
            current_keys.append(content.get('privateKey'))

    if is_lists_equal(current_keys, private_keys):
        click.secho(
            'Keys already synced to the last version.\n',
            bold=True,
            fg='green',
        )
        return

    # save key files
    for index, private_key in enumerate(private_keys):
        filename = f'key_{index}.yaml'
        with open(os.path.join(output_dir, filename), 'w', encoding='utf-8') as f:
            f.write(_generate_key_file(private_key))

    click.secho(
        f'Web3Signer now uses {len(private_keys)} private keys.\n',
        bold=True,
        fg='green',
    )


def _generate_key_file(private_key: str) -> str:
    item = {
        'type': 'file-raw',
        'keyType': 'BLS',
        'privateKey': private_key,
    }
    return yaml.dump(item)
