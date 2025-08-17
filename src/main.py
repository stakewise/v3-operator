import multiprocessing
import os
import ssl
import sys
import warnings
from importlib.metadata import metadata

import click

import src
from src.commands.consolidate import consolidate
from src.commands.create_keys import create_keys
from src.commands.create_wallet import create_wallet
from src.commands.export_public_keys import export_public_keys
from src.commands.import_genesis_keys import import_genesis_keys
from src.commands.init import init
from src.commands.nodes.node_install import node_install
from src.commands.nodes.node_start import node_start
from src.commands.nodes.node_status import node_status
from src.commands.rated_self_report import rated_self_report
from src.commands.recover import recover
from src.commands.remote_signer_setup import remote_signer_setup
from src.commands.start.hashi_vault import start_hashi_vault
from src.commands.start.local import start_local
from src.commands.start.relayer import start_relayer
from src.commands.start.remote_signer import start_remote_signer
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
cli.add_command(consolidate)
cli.add_command(export_public_keys)
cli.add_command(remote_signer_setup)
cli.add_command(create_wallet)
cli.add_command(validators_exit)
cli.add_command(start_local)
cli.add_command(start_local, name='start')  # alias for start_local
cli.add_command(start_hashi_vault)
cli.add_command(start_remote_signer)
cli.add_command(start_relayer)
cli.add_command(recover)
cli.add_command(import_genesis_keys)
cli.add_command(remote_db_group)
cli.add_command(rated_self_report)
cli.add_command(node_install)
cli.add_command(node_start)
cli.add_command(node_status)


if __name__ == '__main__':
    # Pyinstaller hacks
    warnings.filterwarnings('ignore', category=DeprecationWarning)

    eth_typing_metadata = metadata('eth-typing')
    ssz_metadata = metadata('ssz')
    multiprocessing.set_start_method('spawn')
    multiprocessing.freeze_support()
    # Use certificate from certifi only if cafile could not find by ssl.
    if ssl.get_default_verify_paths().cafile is None and hasattr(sys, '_MEIPASS'):
        # pylint: disable-next=protected-access,no-member
        os.environ['SSL_CERT_FILE'] = os.path.join(sys._MEIPASS, 'certifi', 'cacert.pem')

    cli()
