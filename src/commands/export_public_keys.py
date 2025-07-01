import asyncio
import logging
import sys
from pathlib import Path

import click

from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.config.config import OperatorConfig, OperatorConfigException
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import PUBLIC_KEYS_FILENAME, settings
from src.validators.keystores.local import LocalKeystore
from src.validators.utils import save_public_keys

logger = logging.getLogger(__name__)


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the keystores and config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--keystores-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='KEYSTORES_DIR',
    help='Absolute path to the directory with all the encrypted keystores. '
    'Default is the directory generated with "create-keys" command.',
)
@click.option(
    '--network',
    help='The network of your vault.',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.option(
    '--log-level',
    type=click.Choice(
        LOG_LEVELS,
        case_sensitive=False,
    ),
    default='INFO',
    envvar='LOG_LEVEL',
    help='The log level.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.command(
    help='Fetch available public keys from local keystores and export them to validators.txt.'
)
# pylint: disable-next=too-many-arguments
def export_public_keys(
    data_dir: str,
    keystores_dir: str | None,
    network: str | None,
    verbose: bool,
    log_level: str,
) -> None:
    setup_logging()
    try:
        operator_config = OperatorConfig(Path(data_dir))
        operator_config.load(network)
    except OperatorConfigException as e:
        raise click.ClickException(str(e))
    network = operator_config.network

    settings.set(
        vaults=[],
        network=network,
        data_dir=operator_config.data_dir,
        keystores_dir=keystores_dir,
        verbose=verbose,
        log_level=log_level,
    )

    try:
        asyncio.run(main())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main() -> None:
    logger.info('Loading keystores from %s...', settings.keystores_dir)
    public_keys = LocalKeystore.get_public_keys_from_keystore_files()
    filename = settings.data_dir / PUBLIC_KEYS_FILENAME
    if filename.exists():
        click.confirm(
            f'Remove existing {PUBLIC_KEYS_FILENAME} file?',
            default=True,
            abort=True,
        )
    save_public_keys(public_keys=public_keys, filename=filename)
    logger.info('Saved %d public keys to validators.txt', len(public_keys))
