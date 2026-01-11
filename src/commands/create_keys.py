from multiprocessing import Pool
from pathlib import Path

import click
from eth_typing import ChecksumAddress

from src.common.credentials import Credential, CredentialManager
from src.common.password import generate_password, get_or_create_password_file
from src.common.utils import greenify
from src.common.validators import validate_eth_address, validate_mnemonic
from src.config.config import OperatorConfig


@click.option(
    '--vault',
    help='The address of the vault.',
    prompt='Enter the vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the keystores and config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--per-keystore-password',
    is_flag=True,
    help='Creates separate password file for each keystore.'
    ' Creates a single password file by default. Default is false.',
)
@click.option(
    '--mnemonic',
    help='The mnemonic for generating the validator keys.',
    prompt='Enter the mnemonic for generating the validator keys',
    type=str,
    hide_input=True,
    callback=validate_mnemonic,
)
@click.option(
    '--count',
    help='The number of the validator keys to generate.',
    prompt='Enter the number of the validator keys to generate',
    type=click.IntRange(min=1),
)
@click.option(
    '--concurrency',
    help='Number of processes in a pool. The default is 1.',
    envvar='CONCURRENCY',
    type=int,
)
@click.command(help='Creates the validator keys from the mnemonic.')
# pylint: disable-next=too-many-arguments
def create_keys(
    vault: ChecksumAddress,
    mnemonic: str,
    count: int,
    data_dir: str,
    per_keystore_password: bool,
    concurrency: int | None,
) -> None:
    operator_config = OperatorConfig(vault, Path(data_dir))
    operator_config.load(mnemonic)

    credentials = CredentialManager.generate_credentials(
        network=operator_config.network,
        mnemonic=mnemonic,
        count=count,
        start_index=operator_config.mnemonic_next_index,
        concurrency=concurrency,
    )

    # first generate files in tmp directory
    operator_config.create_tmp_dir()
    tmp_keystores_dir = operator_config.tmp_vault_dir / 'keystores'
    try:
        _export_keystores(
            credentials=credentials,
            keystores_dir=tmp_keystores_dir,
            password_file=operator_config.keystores_password_file,
            per_keystore_password=per_keystore_password,
            concurrency=concurrency,
        )
        operator_config.increment_mnemonic_index(count)

        # move files from tmp dir
        operator_config.keystores_dir.mkdir(exist_ok=True)
        for src_file in tmp_keystores_dir.iterdir():
            src_file.rename(operator_config.keystores_dir / src_file.name)

    finally:
        operator_config.remove_tmp_dir()

    click.echo(
        f'Done. Generated {greenify(count)} keys for StakeWise operator.\n'
        f'Keystores saved to {greenify(operator_config.keystores_dir)} file\n'
    )


def _export_keystores(
    credentials: list[Credential],
    keystores_dir: Path,
    password_file: Path,
    per_keystore_password: bool,
    concurrency: int | None = None,
) -> None:
    keystores_dir.mkdir(exist_ok=True)

    if not per_keystore_password:
        password = get_or_create_password_file(password_file)
    with (
        click.progressbar(
            credentials,
            label='Exporting validator keystores\t\t',
            show_percent=False,
            show_pos=True,
        ) as progress_bar,
        Pool(processes=concurrency) as pool,
    ):
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
