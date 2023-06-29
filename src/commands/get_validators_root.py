import logging

import click

from src.common.validators import validate_eth_address
from src.setup_config import setup_config
from src.validators.utils import load_deposit_data

logger = logging.getLogger(__name__)


@click.option(
    '--vault',
    type=str,
    help='Address of the Vault to check deposit data for',
    callback=validate_eth_address,
)
@click.option(
    '--data-dir',
    required=False,
    help='Path where the vault data is placed. Defaults to ~/.stakewise/<vault>',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.option('--execution-endpoint', type=str, help='API endpoint for the execution node')
@click.command(help='Compares deposit data in the vault contract and the vault data directory')
def get_validators_root(*args, **kwargs) -> None:
    setup_config(*args, **kwargs)

    deposit_data = load_deposit_data()
    click.echo(deposit_data.tree.root)
