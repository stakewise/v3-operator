from pathlib import Path

import click
from eth_typing import ChecksumAddress

from src.common.language import LANGUAGES, create_new_mnemonic
from src.common.validators import validate_eth_address
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import DEFAULT_NETWORK


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the keystores and config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.option(
    '--no-verify',
    is_flag=True,
    help='Skips mnemonic verification when provided. Default is false.',
)
@click.option(
    '--language',
    default='english',
    prompt='Choose your mnemonic language',
    type=click.Choice(
        LANGUAGES,
        case_sensitive=False,
    ),
)
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='The vault address.',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--network',
    default=DEFAULT_NETWORK,
    help='The network of your vault.',
    prompt='Enter the network name',
    envvar='NETWORK',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Initializes config data directory and generates mnemonic.')
def init(
    language: str,
    no_verify: bool,
    vault: ChecksumAddress,
    network: str,
    data_dir: str,
) -> None:
    config = OperatorConfig(
        vault=vault,
        data_dir=Path(data_dir),
    )
    if config.config_path.is_file():
        raise click.ClickException(f'Config directory {config.vault_dir} already exists.')

    if not language:
        language = click.prompt(
            'Choose your mnemonic language',
            default='english',
            type=click.Choice(LANGUAGES, case_sensitive=False),
        )
    mnemonic = create_new_mnemonic(language, skip_test=no_verify)

    config.save(network, mnemonic)
    if not no_verify:
        click.secho(
            'Successfully initialized configuration for StakeWise operator', bold=True, fg='green'
        )
