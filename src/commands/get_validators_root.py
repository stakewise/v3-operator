import os
from pathlib import Path

import click
from eth_typing import HexAddress

from src.common.utils import greenify
from src.common.validators import validate_eth_address
from src.validators.utils import load_deposit_data


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--deposit-data-file',
    required=False,
    help='Path to the deposit data file. Default is ~/.stakewise/<vault>/deposit_data.json.',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    '--vault',
    help='The address of the vault.',
    prompt='Enter the vault address',
    type=str,
    callback=validate_eth_address,
)
@click.command(help='Calculates Merkle tree root for the deposit data file.')
def get_validators_root(vault: HexAddress, data_dir: str, deposit_data_file: str | None) -> None:
    if deposit_data_file:
        file_path = Path(str(deposit_data_file))
    else:
        file_path = Path(data_dir) / vault.lower() / 'deposit_data.json'

    if not os.path.isfile(file_path):
        raise click.ClickException(
            'Deposit data file does not exist. Have you called "create-keys" command?'
        )

    deposit_data = load_deposit_data(vault, file_path)
    click.echo(f'The validator deposit data Merkle tree root: {greenify(deposit_data.tree.root)}')
