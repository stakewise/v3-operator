import json
from os import path
from pathlib import Path

import click
from eth_account import Account
from eth_typing import ChecksumAddress, HexAddress

from src.common.password import get_or_create_password_file
from src.common.utils import greenify
from src.common.validators import validate_eth_address, validate_mnemonic
from src.common.vault_config import VaultConfig


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--mnemonic',
    help='The mnemonic for generating the wallet.',
    prompt='Enter the mnemonic for generating the wallet',
    type=str,
    callback=validate_mnemonic,
)
@click.option(
    '--vault',
    help='The address of the vault.',
    prompt='Enter the vault address',
    type=str,
    callback=validate_eth_address,
)
@click.command(help='Creates the encrypted hot wallet from the mnemonic.')
def create_wallet(mnemonic: str, vault: HexAddress, data_dir: str) -> None:
    vault_config = VaultConfig(vault, Path(data_dir))
    vault_config.load()
    wallet_dir = vault_config.vault_dir / 'wallet'

    wallet_dir.mkdir(parents=True, exist_ok=True)
    address = _generate_encrypted_wallet(mnemonic, wallet_dir)
    click.echo(
        f'Done. '
        f'The wallet and password saved to {greenify(wallet_dir)} directory. '
        f'The wallet address is: {greenify(address)}'
    )


def _generate_encrypted_wallet(mnemonic: str, wallet_dir: Path) -> ChecksumAddress:
    Account.enable_unaudited_hdwallet_features()

    account = Account().from_mnemonic(mnemonic=mnemonic)
    password = get_or_create_password_file(wallet_dir / 'password.txt')
    encrypted_data = Account.encrypt(account.key, password=password)

    wallet_name = 'wallet.json'
    with open(path.join(wallet_dir, wallet_name), 'w', encoding='utf-8') as f:
        json.dump(encrypted_data, f, default=lambda x: x.hex())
    return account.address
