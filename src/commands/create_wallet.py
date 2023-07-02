import json
from os import path
from pathlib import Path

import click
from eth_account import Account
from eth_typing import ChecksumAddress, HexAddress

from src.common.contrib import greenify
from src.common.password import get_or_create_password_file
from src.common.validators import validate_eth_address, validate_mnemonic
from src.config.settings import DATA_DIR


@click.option(
    '--mnemonic',
    help='The mnemonic for generating the wallet.',
    prompt='Enter the mnemonic for generating the wallet',
    type=str,
    callback=validate_mnemonic,
)
@click.option(
    '--vault',
    '--withdrawal-address',
    help='The withdrawal address where the funds will be sent after validators withdrawals.',
    prompt='Enter the Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--data-dir',
    required=False,
    help='Path where the vault data will be placed. ' 'Defaults to ~/.stakewise/<vault>',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.command(help='Creates the encrypted hot wallet from the mnemonic.')
def create_wallet(mnemonic: str, vault: HexAddress, data_dir: str) -> None:
    wallet_dir = Path(f'{data_dir or DATA_DIR}/{vault.lower()}/wallet')
    wallet_dir.mkdir(parents=True, exist_ok=True)
    address = _generate_encrypted_wallet(mnemonic, str(wallet_dir))
    click.echo(
        f'Done. '
        f'The wallet and password saved to {greenify(wallet_dir)} directory. '
        f'The Wallet address is: {greenify(address)}'
    )


def _generate_encrypted_wallet(mnemonic: str, wallet_dir: str) -> ChecksumAddress:
    Account.enable_unaudited_hdwallet_features()

    account = Account().from_mnemonic(mnemonic=mnemonic)
    password = get_or_create_password_file(path.join(wallet_dir, 'password.txt'))
    encrypted_data = Account.encrypt(account.key, password=password)

    wallet_name = 'wallet.json'
    with open(path.join(wallet_dir, wallet_name), 'w', encoding='utf-8') as f:
        json.dump(encrypted_data, f, default=lambda x: x.hex())
    return account.address
