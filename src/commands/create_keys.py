from multiprocessing import Pool
from os import path
from pathlib import Path

import click

from src.common.credentials import Credential, CredentialManager
from src.common.password import generate_password, get_or_create_password_file
from src.common.utils import greenify
from src.common.validators import validate_mnemonic
from src.config.config import OperatorConfig, OperatorConfigException
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import PUBLIC_KEYS_FILENAME, settings
from src.validators.keystores.local import LocalKeystore
from src.validators.utils import save_public_keys


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
    default=False,
    help='Creates separate password file for each keystore.',
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
    '--pool-size',
    help='Number of processes in a pool.',
    envvar='POOL_SIZE',
    type=int,
)
@click.option(
    '--network',
    help='The network of your vault.',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Creates the validator keys from the mnemonic.')
# pylint: disable-next=too-many-arguments,too-many-locals
def create_keys(
    mnemonic: str,
    count: int,
    data_dir: str,
    per_keystore_password: bool,
    pool_size: int | None,
    network: str | None,
) -> None:
    try:
        operator_config = OperatorConfig(Path(data_dir))
        operator_config.load(network, mnemonic)
    except OperatorConfigException as e:
        raise click.ClickException(str(e))
    settings.set(
        vaults=[],
        network=operator_config.network,
        data_dir=operator_config.data_dir,
    )

    credentials = CredentialManager.generate_credentials(
        network=operator_config.network,
        mnemonic=mnemonic,
        count=count,
        start_index=operator_config.mnemonic_next_index,
        pool_size=pool_size,
    )

    # first generate files in tmp directory
    operator_config.create_tmp_dir()
    tmp_public_keys_file = operator_config.tmp_data_dir / PUBLIC_KEYS_FILENAME
    tmp_keystores_dir = operator_config.tmp_data_dir / 'keystores'
    try:
        _export_keystores(
            credentials=credentials,
            keystores_dir=tmp_keystores_dir,
            password_file=operator_config.keystores_password_file,
            per_keystore_password=per_keystore_password,
            pool_size=pool_size,
        )
        public_keys = LocalKeystore.get_public_keys_from_keystore_files()
        public_keys.extend([c.public_key for c in credentials])
        save_public_keys(public_keys=public_keys, filename=tmp_public_keys_file)
        operator_config.increment_mnemonic_index(count)

        # move files from tmp dir
        operator_config.keystores_dir.mkdir(exist_ok=True)
        tmp_public_keys_file.replace(operator_config.public_keys_file)
        for src_file in tmp_keystores_dir.glob('*'):
            src_file.rename(operator_config.keystores_dir.joinpath(src_file.name))

    finally:
        operator_config.remove_tmp_dir()

    click.echo(
        f'Done. Generated {greenify(count)} keys for StakeWise operator.\n'
        f'Keystores saved to {greenify(operator_config.keystores_dir)} file\n'
        'Validator public keys saved to '
        f'{greenify(path.abspath(operator_config.public_keys_file))} file'
    )


def _export_keystores(
    credentials: list[Credential],
    keystores_dir: Path,
    password_file: Path,
    per_keystore_password: bool,
    pool_size: int | None = None,
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
        Pool(processes=pool_size) as pool,
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
