import json
from multiprocessing import Pool
from os import makedirs, path

import click
from eth_typing import HexAddress

from src.common.config import Config
from src.common.contrib import async_command, greenify
from src.common.credentials import Credential, CredentialManager
from src.common.password import get_or_create_password_file
from src.common.validators import validate_eth_address, validate_mnemonic


@click.option(
    '--mnemonic',
    help='The mnemonic for generating the validator keys.',
    prompt='Enter the mnemonic for generating the validator keys',
    type=str,
    callback=validate_mnemonic,
)
@click.option(
    '--count',
    help='The number of the validator keys to generate.',
    prompt='Enter the number of the validator keys to generate',
    type=click.IntRange(min=1),
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
    help='Path where the vault data will be placed. '
    'Defaults to ~/.stakewise/<vault>',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.command(help='Creates the validator keys from the mnemonic.')
@async_command
async def create_keys(
    mnemonic: str,
    count: int,
    vault: HexAddress,
    data_dir: str,
) -> None:
    config = Config(vault=vault, data_dir=data_dir)
    config.load()

    first_public_key = CredentialManager.generate_credential_first_public_key(
        config.network, vault, str(mnemonic)
    )
    if first_public_key != config.first_public_key:
        raise click.ClickException(
            'Invalid mnemonic. Please use mnemonic provided at init command.'
        )

    deposit_data_file = config.data_dir / 'deposit_data.json'
    keystores_dir = config.data_dir / 'keystores'
    password_file = keystores_dir / 'password.txt'

    credentials = CredentialManager.generate_credentials(
        network=config.network,
        vault=vault,
        mnemonic=mnemonic,
        count=count,
        start_index=config.mnemonic_next_index,
    )
    deposit_data = _export_deposit_data_json(
        credentials=credentials,
        filename=str(deposit_data_file)
    )

    _export_keystores(
        credentials=credentials,
        keystores_dir=str(keystores_dir),
        password_file=str(password_file)
    )

    config.update(mnemonic_next_index=config.mnemonic_next_index+count)

    click.echo(
        f'Done. Generated {greenify(count)} keys for {greenify(vault)} vault.\n'
        f'Keystores saved to {greenify(keystores_dir)} file\n'
        f'Deposit data saved to {greenify(deposit_data)} file'
    )


def _export_deposit_data_json(credentials: list[Credential], filename: str) -> str:
    with click.progressbar(
        length=len(credentials),
        label='Generating deposit data JSON\t\t',
        show_percent=False,
        show_pos=True,
    ) as bar, Pool() as pool:
        results = [
            pool.apply_async(
                cred.deposit_datum_dict,
                callback=lambda x: bar.update(1),
            )
            for cred in credentials
        ]
        for result in results:
            result.wait()
        deposit_data = [result.get() for result in results]

    makedirs(path.dirname(path.abspath(filename)), exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(deposit_data, f, default=lambda x: x.hex())
    return filename


def _export_keystores(
    credentials: list[Credential], keystores_dir: str, password_file: str
) -> None:
    makedirs(path.abspath(keystores_dir), exist_ok=True)
    password = get_or_create_password_file(password_file)
    with click.progressbar(
        credentials,
        label='Exporting validator keystores\t\t',
        show_percent=False,
        show_pos=True,
    ) as bar, Pool() as pool:
        results = [
            pool.apply_async(
                cred.save_signing_keystore,
                kwds={'password': password, 'folder': keystores_dir},
                callback=lambda x: bar.update(1),
            )
            for cred in credentials
        ]

        for result in results:
            result.wait()
