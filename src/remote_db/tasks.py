import base64
import json
from pathlib import Path

import click
import milagro_bls_binding as bls
import yaml
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from eth_typing import ChecksumAddress, HexStr
from web3 import Web3

from src.common.utils import greenify
from src.config.settings import settings
from src.remote_db.database import KeyPairsCrud, get_db_connection
from src.remote_db.typings import RemoteDatabaseKeyPair
from src.validators.keystores.local import LocalKeystore
from src.validators.typings import BLSPrivkey

CIPHER_KEY_LENGTH = 32
VALIDATOR_DEFINITIONS_FILENAME = 'validator_definitions.yml'
SIGNER_KEYS_FILENAME = 'signer_keys.yml'
PROPOSER_CONFIG_FILENAME = 'proposer_config.json'


def setup(db_url: str) -> str:
    """Checks remote db, creates tables and generates encryption key."""
    # create tables
    with get_db_connection(db_url) as conn:
        keypairs_crud = KeyPairsCrud(db_connection=conn)
        keypairs_crud.create_table()

        if keypairs_crud.get_keypairs_count() > 0:
            raise click.ClickException(
                'Error: the remote database is not empty. '
                'Please clean up with "clean" command first.',
            )

    # generate encryption key
    encryption_key = get_random_bytes(CIPHER_KEY_LENGTH)
    return base64.b64encode(encryption_key).decode('ascii')


def cleanup(db_url: str) -> None:
    """Clean up remote db entries for the vault."""
    with get_db_connection(db_url) as conn:
        keypairs_crud = KeyPairsCrud(db_connection=conn)
        keypairs_crud.remove_keypairs()


# pylint: disable=too-many-locals
async def upload_keypairs(db_url: str, b64_encrypt_key: str) -> None:
    """Uploads key-pairs to remote DB. Updates configs in the remote DB."""
    encryption_key = _check_encryption_key(db_url, b64_encrypt_key)

    click.echo(f'Loading keystores from {settings.keystores_dir}...')
    keystore = await LocalKeystore.load()
    if len(keystore) == 0:
        raise click.ClickException('Keystore not found.')

    click.echo(f'Encrypting {len(keystore)} keystores...')
    key_records: list[RemoteDatabaseKeyPair] = []
    for public_key, private_key in keystore.keys.items():  # pylint: disable=no-member
        encrypted_priv_key, nonce = _encrypt_private_key(private_key, encryption_key)
        key_records.append(
            RemoteDatabaseKeyPair(
                public_key=public_key,
                private_key=Web3.to_hex(encrypted_priv_key),
                nonce=Web3.to_hex(nonce),
            )
        )

    click.echo('Uploading updates to the remote db...')
    with get_db_connection(db_url) as conn:
        keypairs_crud = KeyPairsCrud(db_connection=conn)
        # upload keypairs to remote db
        keypairs_crud.upload_keypairs(key_records)


def setup_web3signer(db_url: str, b64_encrypt_key: str, output_dir: Path) -> None:
    """Fetch and decrypt keys for web3signer and store them as keypairs in the output_dir."""
    encryption_key = _check_encryption_key(db_url, b64_encrypt_key)

    click.echo('Fetching keypairs from the remote db...')
    keypairs = KeyPairsCrud(db_url=db_url).get_keypairs()
    if len(keypairs) == 0:
        raise click.ClickException('No keypairs found in the remote db.')

    click.echo(f'Decrypting {len(keypairs)} keystores...')
    private_keys: set[HexStr] = set()
    for keypair in keypairs:
        decrypted_private_key = _decrypt_private_key(
            private_key=Web3.to_bytes(hexstr=keypair.private_key),
            encryption_key=encryption_key,
            nonce=Web3.to_bytes(hexstr=keypair.nonce),
        )
        private_keys.add(Web3.to_hex(decrypted_private_key))

    click.echo(f'Saving {len(private_keys)} private keys to {output_dir}...')
    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)

    sorted_private_keys = sorted(list(private_keys))
    for index, private_key in enumerate(sorted_private_keys):
        filename = f'key_{index}.yaml'
        data = {
            'type': 'file-raw',
            'keyType': 'BLS',
            'privateKey': private_key,
        }
        with open(output_dir / filename, 'w', encoding='utf-8') as f:
            f.write(yaml.dump(data))


# pylint: disable=too-many-arguments
def setup_validator(
    db_url: str,
    total_validators: int,
    validator_index: int,
    web3signer_endpoint: str,
    fee_recipient: ChecksumAddress,
    disable_proposal_builder: bool,
    output_dir: Path,
) -> None:
    """Generate validator configs for Lighthouse, Teku and Prysm clients."""
    keypairs = KeyPairsCrud(db_url=db_url).get_keypairs()
    if not keypairs:
        raise click.ClickException('No keypairs found in the remote db.')

    public_keys_count = len(keypairs)
    start_index, end_index = _get_key_indexes(
        public_keys_count=public_keys_count,
        validator_index=validator_index,
        total_validators=total_validators,
    )
    if not 0 <= start_index < end_index <= public_keys_count:
        raise click.ClickException('Invalid validator index')

    # get public keys for validator
    public_keys = [keypair.public_key for keypair in keypairs[start_index:end_index]]
    if not public_keys:
        raise click.ClickException('Failed to get range of public keys for the validator.')

    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)

    # lighthouse
    validator_definitions_filepath = output_dir / VALIDATOR_DEFINITIONS_FILENAME
    _generate_lighthouse_config(
        public_keys=public_keys,
        web3signer_url=web3signer_endpoint,
        fee_recipient=fee_recipient,
        filepath=validator_definitions_filepath,
    )

    # teku/prysm
    signer_keys_filepath = output_dir / SIGNER_KEYS_FILENAME
    _generate_signer_keys_config(public_keys=public_keys, filepath=signer_keys_filepath)

    proposer_config_filepath = output_dir / PROPOSER_CONFIG_FILENAME
    _generate_proposer_config(
        fee_recipient=fee_recipient,
        proposal_builder_enabled=not disable_proposal_builder,
        filepath=proposer_config_filepath,
    )

    click.secho(
        f'Generated configs with {greenify(len(public_keys))} keys '
        f'for validator with index {greenify(f"{validator_index}")}.\n'
        f'Validator definitions for Lighthouse saved to '
        f'{greenify(validator_definitions_filepath)} file.\n'
        f'Signer keys for Teku\\Prysm saved to '
        f'{greenify(signer_keys_filepath)} file.\n'
        f'Proposer config for Teku\\Prysm saved to '
        f'{greenify(proposer_config_filepath)} file.\n',
    )


def setup_operator(db_url: str, output_dir: Path) -> None:
    """Create operator remote signer configuration."""
    keypairs_crud = KeyPairsCrud(db_url=db_url)

    public_keys = keypairs_crud.get_public_keys()
    if public_keys is None:
        raise click.ClickException('No keystores found in the remote db.')

    if not output_dir.exists():
        output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / 'validators.txt'
    with open(output_file, 'w', encoding='utf-8') as f:
        for public_key in public_keys:
            f.write(f'{public_key}\n')

    click.secho(f'Operator validators saved to {greenify(output_file)} file.')


def _check_encryption_key(db_url: str, b64_encrypt_key: str) -> bytes:
    try:
        encryption_key = base64.b64decode(b64_encrypt_key)
        if len(encryption_key) != CIPHER_KEY_LENGTH:
            raise click.ClickException('Invalid encryption key length.')
    except Exception as exc:
        raise click.ClickException('Invalid encryption key.') from exc

    keypair = KeyPairsCrud(db_url=db_url).get_first_keypair()
    if keypair is None:
        return encryption_key

    try:
        decrypted_private_key = _decrypt_private_key(
            private_key=Web3.to_bytes(hexstr=keypair.private_key),
            encryption_key=encryption_key,
            nonce=Web3.to_bytes(hexstr=keypair.nonce),
        )
    except Exception as e:
        raise click.ClickException('Failed to decrypt first private key.') from e

    if bls.SkToPk(decrypted_private_key) != Web3.to_bytes(hexstr=keypair.public_key):
        raise click.ClickException('Failed to decrypt first private key.')

    return encryption_key


def _encrypt_private_key(private_key: BLSPrivkey, encryption_key: bytes) -> tuple[bytes, bytes]:
    cipher = AES.new(encryption_key, AES.MODE_EAX)
    return cipher.encrypt(private_key), cipher.nonce


def _decrypt_private_key(private_key: bytes, encryption_key: bytes, nonce: bytes) -> BLSPrivkey:
    cipher = AES.new(encryption_key, AES.MODE_EAX, nonce=nonce)
    return BLSPrivkey(cipher.decrypt(private_key))


def _generate_lighthouse_config(
    public_keys: list[HexStr],
    web3signer_url: str,
    fee_recipient: str,
    filepath: Path,
) -> None:
    """Generate config for Lighthouse client"""
    items = [
        {
            'enabled': True,
            'voting_public_key': public_key,
            'type': 'web3signer',
            'url': web3signer_url,
            'suggested_fee_recipient': fee_recipient,
        }
        for public_key in public_keys
    ]

    with open(filepath, 'w', encoding='utf-8') as f:
        yaml.dump(items, f, explicit_start=True)


def _generate_signer_keys_config(public_keys: list[HexStr], filepath: Path) -> None:
    """
    Generate config for Teku and Prysm clients
    """
    keys = ','.join([f'"{public_key}"' for public_key in public_keys])
    config = f"""validators-external-signer-public-keys: [{keys}]"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(config)


def _generate_proposer_config(
    fee_recipient: str,
    proposal_builder_enabled: bool,
    filepath: Path,
) -> None:
    """
    Generate proposal config for Teku and Prysm clients
    """
    config = {
        'default_config': {
            'fee_recipient': fee_recipient,
            'builder': {
                'enabled': proposal_builder_enabled,
            },
        },
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)


def _get_key_indexes(
    public_keys_count: int,
    total_validators: int,
    validator_index: int,
) -> tuple[int, int]:
    keys_per_validator = (public_keys_count - 1) // total_validators + 1
    start_index = keys_per_validator * validator_index
    end_index = min(start_index + keys_per_validator, public_keys_count)
    return start_index, end_index
