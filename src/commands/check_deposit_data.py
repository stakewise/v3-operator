import asyncio
import logging
import sys

import click

from src.common.validators import validate_eth_address
from src.setup_config import setup_config
from src.setup_logging import setup_logging
from src.validators.execution import check_deposit_data_root
from src.validators.utils import load_deposit_data

logger = logging.getLogger(__name__)


# Error codes are used by Nodewise.
#
# Standard python exit codes:
# 0 - success
# 1 - error
DEPOSIT_DATA_ROOT_ERROR = 2


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
def check_deposit_data(*args, **kwargs) -> None:
    setup_config(*args, **kwargs)
    setup_logging()
    try:
        asyncio.run(_check_deposit_data())
    except RuntimeError as e:
        logger.error(repr(e))
        sys.exit(DEPOSIT_DATA_ROOT_ERROR)


async def _check_deposit_data() -> None:
    deposit_data = await load_deposit_data()
    await check_deposit_data_root(deposit_data.tree.root)
