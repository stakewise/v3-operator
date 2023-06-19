import asyncio
import logging
import sys

import click

from src.commands.common import setup_config, setup_logging
from src.common.validators import validate_eth_address
from src.config.settings import AVAILABLE_NETWORKS
from src.validators.execution import check_deposit_data_root
from src.validators.utils import load_deposit_data

logger = logging.getLogger(__name__)


# Error codes are used by Nodewise.
#
# Standard python exit codes:
# 0 - success
# 1 - error
DEPOSIT_DATA_ROOT_ERROR = 2


async def check_deposit_data() -> None:
    deposit_data = await load_deposit_data()
    await check_deposit_data_root(deposit_data.tree.root)


@click.option(
    '--network',
    required=False,
    help='The network of the Vault',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.option(
    '--vault',
    type=str,
    help='Address of the Vault to register validators for',
    callback=validate_eth_address,
)
@click.option(
    '--data-dir',
    required=False,
    help='Path where the vault data is placed. Defaults to ~/.stakewise/<vault>',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.option(
    '--database-dir', type=str, help='The directory where the database will be created or read from'
)
@click.option('--execution-endpoint', type=str, help='API endpoint for the execution node')
@click.option('--consensus-endpoint', type=str, help='API endpoint for the consensus node')
@click.option('--max-fee-per-gas-gwei', type=int, help='Maximum fee per gas limit')
@click.option('--harvest-vault', type=bool, help='Periodically submit vault harvest transaction')
@click.option(
    '--keystores-password-file',
    type=str,
    help='Absolute path to the password file for decrypting keystores',
)
@click.option(
    '--keystores-password-dir',
    type=str,
    help='Absolute path to the password directory for decrypting keystores',
)
@click.option(
    '--keystores-path',
    type=str,
    help='Absolute path to the directory with all the encrypted keystores',
)
@click.option('--deposit-data-path', type=str, help='Path to the deposit_data.json file')
@click.option(
    '--hot-wallet-private-key',
    type=str,
    help='Private key of the hot wallet for submitting transactions',
)
@click.option('--hot-wallet-keystore-path', type=str, help='Absolute path to the hot wallet')
@click.option(
    '--hot-wallet-keystore-password-path',
    type=str,
    help='Absolute path to the password file for hot wallet',
)
@click.option('-v', '--verbose', help='Enable debug mode', is_flag=True)
@click.command(name='check_deposit_data', help='check deposit data')
def check_deposit_data_cmd(*args, **kwargs) -> None:
    setup_config(*args, **kwargs)
    setup_logging()
    try:
        asyncio.run(check_deposit_data())
    except RuntimeError as e:
        logger.error(repr(e))
        sys.exit(DEPOSIT_DATA_ROOT_ERROR)
