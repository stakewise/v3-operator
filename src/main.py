import multiprocessing
import warnings
from importlib.metadata import metadata

import click

import src
from src.commands.consolidate import consolidate
from src.commands.create_keys import create_keys
from src.commands.create_wallet import create_wallet
from src.commands.exit_validators import exit_validators
from src.commands.init import init
from src.commands.internal.process_redeemer import process_redeemer
from src.commands.internal.update_redeemable_positions import (
    update_redeemable_positions,
)
from src.commands.nodes.node_install import node_install
from src.commands.nodes.node_start import node_start
from src.commands.nodes.node_status import node_status_command as node_status
from src.commands.process_meta_vaults import process_meta_vaults
from src.commands.recover import recover
from src.commands.setup_remote_signer import setup_remote_signer
from src.commands.start.hashi_vault import start_hashi_vault
from src.commands.start.local import start_local
from src.commands.start.relayer import start_relayer
from src.commands.start.remote_signer import start_remote_signer
from src.commands.submit_rated_network import submit_rated_network
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
cli.add_command(process_meta_vaults)
cli.add_command(setup_remote_signer)
cli.add_command(create_wallet)
cli.add_command(exit_validators)
cli.add_command(start_local)
cli.add_command(start_local, name='start')  # alias for start_local
cli.add_command(start_hashi_vault)
cli.add_command(start_remote_signer)
cli.add_command(start_relayer)
cli.add_command(recover)
cli.add_command(remote_db_group)
cli.add_command(submit_rated_network)
cli.add_command(node_install)
cli.add_command(node_start)
cli.add_command(node_status)
cli.add_command(update_redeemable_positions)
cli.add_command(process_redeemer)


if __name__ == '__main__':
    # Pyinstaller hacks
    warnings.filterwarnings('ignore', category=DeprecationWarning)

    eth_typing_metadata = metadata('eth-typing')
    ssz_metadata = metadata('ssz')
    multiprocessing.set_start_method('spawn')
    multiprocessing.freeze_support()

    cli()
