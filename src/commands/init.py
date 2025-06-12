from pathlib import Path

import click

from src.common.language import LANGUAGES, create_new_mnemonic
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
    help='Skips mnemonic verification when provided.',
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
    '--network',
    default=DEFAULT_NETWORK,
    help='The network of your vault.',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Initializes config data directory and generates mnemonic.')
def init(
    language: str,
    no_verify: bool,
    network: str,
    data_dir: str,
) -> None:
    config = OperatorConfig(
        data_dir=Path(data_dir),
    )
    if config.exists:
        raise click.ClickException(f'Config directory {config.data_dir} already exists.')

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
