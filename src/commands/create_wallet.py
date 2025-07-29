import json
from os import path
from pathlib import Path

import click
from eth_account import Account
from eth_typing import ChecksumAddress

from src.common.password import get_or_create_password_file
from src.common.utils import greenify
from src.common.validators import validate_mnemonic
from src.config.config import OperatorConfig, OperatorConfigException
from src.config.networks import AVAILABLE_NETWORKS


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the keystores and config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--mnemonic',
    help='The mnemonic for generating the wallet.',
    prompt='Enter the mnemonic for generating the wallet',
    type=str,
    hide_input=True,
    callback=validate_mnemonic,
)
@click.option(
    '--network',
    help='The network of your vault.',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Creates the encrypted wallet from the mnemonic.')
def create_wallet(mnemonic: str, data_dir: str, network: str | None) -> None:
    try:
        operator_config = OperatorConfig(Path(data_dir))
        operator_config.load(network, mnemonic)
    except OperatorConfigException as e:
        raise click.ClickException(str(e))
    wallet_dir = operator_config.data_dir / 'wallet'

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
