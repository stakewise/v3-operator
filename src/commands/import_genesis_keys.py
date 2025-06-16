import glob
import os
from pathlib import Path
from typing import Dict

import click
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from eth_typing import BLSPrivateKey, ChecksumAddress, HexStr
from py_ecc.bls import G2ProofOfPossession
from web3 import Web3

from src.common.credentials import Credential
from src.common.password import get_or_create_password_file
from src.common.typings import ValidatorType
from src.common.utils import greenify
from src.common.validators import validate_eth_address
from src.config.config import OperatorConfig, OperatorConfigException
from src.config.settings import settings


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the keystores and config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--rsa-key',
    help='The RSA private key to decrypt keystores.',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    '--exported-keys-dir',
    help='Path where the encrypted keys are located.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--vault',
    help='The address of the vault.',
    prompt='Enter the vault address',
    type=str,
    callback=validate_eth_address,
)
@click.command(help='Import encrypted keystores. Only for the genesis vault')
# pylint: disable-next=too-many-arguments
def import_genesis_keys(
    rsa_key: str,
    exported_keys_dir: str,
    vault: ChecksumAddress,
    data_dir: str,
) -> None:
    try:
        operator_config = OperatorConfig(Path(data_dir))
        operator_config.load()
    except OperatorConfigException as e:
        raise click.ClickException(str(e))
    network = operator_config.network

    settings.set(
        vaults=[vault],
        network=network,
        data_dir=operator_config.data_dir,
    )
    if settings.network_config.GENESIS_VAULT_CONTRACT_ADDRESS != vault:
        raise click.ClickException('The command is only for the genesis vault.')

    keystores_dir = operator_config.data_dir / 'keystores'
    password_file = keystores_dir / 'password.txt'
    password = get_or_create_password_file(password_file)

    click.secho('Decrypting keystores...', bold=True)

    transferred_keypairs = _decrypt_transferred_keys(
        keys_dir=exported_keys_dir, decrypt_key=rsa_key
    )

    click.secho(f'Saving keystores to {greenify(keystores_dir)}...', bold=True)

    index = 0
    for private_key in transferred_keypairs.values():
        credential = Credential(
            private_key=BLSPrivateKey(private_key),
            network=network,
            path=f'imported_{index}',
            validator_type=ValidatorType.ONE,
        )
        credential.save_signing_keystore(password=password, folder=str(keystores_dir))
        index += 1

    click.echo(
        f'Done. Imported {greenify(len(transferred_keypairs))} keys for {greenify(vault)} vault.\n'
        f'Keystores saved to {greenify(keystores_dir)} file\n'
    )


# pylint: disable-next=too-many-locals
def _decrypt_transferred_keys(keys_dir: str, decrypt_key: str) -> Dict[HexStr, int]:
    keypairs: Dict[HexStr, int] = {}

    with open(decrypt_key, 'r', encoding='utf-8') as f:
        rsa_key = RSA.import_key(f.read())
    for filename in glob.glob(os.path.join(keys_dir, '*.enc')):
        with open(os.path.join(os.getcwd(), filename), 'rb') as f:
            try:
                enc_session_key, nonce, tag, ciphertext = [
                    f.read(x) for x in (rsa_key.size_in_bytes(), 16, 16, -1)
                ]
            except Exception as e:
                raise click.ClickException(f'Invalid encrypted private key file: {filename}') from e

        try:
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            session_key = cipher_rsa.decrypt(enc_session_key)
        except Exception as e:
            raise click.ClickException('Failed to decrypt the private key.') from e

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        try:
            private_key = int(cipher_aes.decrypt_and_verify(ciphertext, tag))
            public_key = Web3.to_hex(G2ProofOfPossession.SkToPk(private_key))
            keypairs[public_key] = private_key
        except Exception as e:
            raise click.ClickException(
                'Failed to decrypt the private key file. Is it corrupted?'
            ) from e

    return keypairs
