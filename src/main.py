import multiprocessing
import os
import ssl
import sys
from importlib.metadata import metadata

import click

import src
from src.commands.create_keys import create_keys
from src.commands.create_wallet import create_wallet
from src.commands.get_validators_root import get_validators_root
from src.commands.init import init
from src.commands.merge_deposit_data import merge_deposit_data
from src.commands.recover import recover
from src.commands.remote_signer_setup import remote_signer_setup
from src.commands.start import start
from src.commands.validators_exit import validators_exit
from src.common.utils import get_build_version
from src.remote_db.commands import remote_db_group

build = get_build_version()
version = src.__version__
if build:
    version += f'-{build}'


@click.version_option(version=version, prog_name='Stakewise v3 operator service')
@click.group()
def cli() -> None:
    pass


cli.add_command(init)
cli.add_command(create_keys)
cli.add_command(remote_signer_setup)
cli.add_command(create_wallet)
cli.add_command(merge_deposit_data)
cli.add_command(validators_exit)
cli.add_command(start)
cli.add_command(recover)
cli.add_command(get_validators_root)
cli.add_command(remote_db_group)

if __name__ == '__main__':
    # Pyinstaller hacks
    eth_typing_metadata = metadata('eth-typing')
    multiprocessing.set_start_method('spawn')
    multiprocessing.freeze_support()
    # Use certificate from certifi only if cafile could not find by ssl.
    if ssl.get_default_verify_paths().cafile is None and hasattr(sys, '_MEIPASS'):
        # pylint: disable-next=protected-access
        os.environ['SSL_CERT_FILE'] = os.path.join(sys._MEIPASS, 'certifi', 'cacert.pem')

    cli()
