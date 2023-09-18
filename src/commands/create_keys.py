import json
from multiprocessing import Pool
from os import makedirs, path
from pathlib import Path

import click
from eth_typing import HexAddress

from src.common.contrib import greenify
from src.common.credentials import Credential, CredentialManager
from src.common.password import generate_password, get_or_create_password_file
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
    '--per-keystore-password',
    is_flag=True,
    default=False,
    help='Creates separate password file for each keystore.',
)
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
    help='The address of the vault.',
    prompt='Enter the vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--pool-size',
    help='Number of processes in a pool.',
    # do not prompt
    type=int,
)
@click.command(help='Creates the validator keys from the mnemonic.')
# pylint: disable-next=too-many-arguments
def create_keys(
    mnemonic: str,
    count: int,
    vault: HexAddress,
    data_dir: str,
    per_keystore_password: bool,
    pool_size: int | None,
) -> None:
    config = VaultConfig(vault, Path(data_dir))
    config.load(mnemonic)

    deposit_data_file = config.vault_dir / 'deposit_data.json'
    keystores_dir = config.vault_dir / 'keystores'
    password_file = keystores_dir / 'password.txt'

    credentials = CredentialManager.generate_credentials(
        network=config.network,
        vault=vault,
        mnemonic=mnemonic,
        count=count,
        start_index=config.mnemonic_next_index,
        pool_size=pool_size,
    )
    deposit_data = _export_deposit_data_json(
        credentials=credentials, filename=str(deposit_data_file), pool_size=pool_size
    )

    _export_keystores(
        credentials=credentials,
        keystores_dir=keystores_dir,
        password_file=str(password_file),
        per_keystore_password=per_keystore_password,
        pool_size=pool_size,
    )

    config.increment_mnemonic_index(count)

    click.echo(
        f'Done. Generated {greenify(count)} keys for {greenify(vault)} vault.\n'
        f'Keystores saved to {greenify(keystores_dir)} file\n'
        f'Deposit data saved to {greenify(deposit_data)} file'
    )


def _export_deposit_data_json(
    credentials: list[Credential], filename: str, pool_size: int | None = None
) -> str:
    with click.progressbar(
        length=len(credentials),
        label='Generating deposit data JSON\t\t',
        show_percent=False,
        show_pos=True,
    ) as progress_bar, Pool(processes=pool_size) as pool:
        results = [
            pool.apply_async(
                cred.deposit_datum_dict,
                callback=lambda x: progress_bar.update(1),
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
    credentials: list[Credential],
    keystores_dir: Path,
    password_file: str,
    per_keystore_password: bool,
    pool_size: int | None = None,
) -> None:
    keystores_dir.mkdir(exist_ok=True)

    if not per_keystore_password:
        password = get_or_create_password_file(password_file)
    with click.progressbar(
        credentials,
        label='Exporting validator keystores\t\t',
        show_percent=False,
        show_pos=True,
    ) as progress_bar, Pool(processes=pool_size) as pool:
        results = [
            pool.apply_async(
                cred.save_signing_keystore,
                kwds={
                    'password': generate_password() if per_keystore_password else password,
                    'folder': str(keystores_dir),
                    'per_keystore_password': per_keystore_password,
                },
                callback=lambda x: progress_bar.update(1),
            )
            for cred in credentials
        ]

        for result in results:
            # Use result.get() to reraise exceptions
            result.get()
