from pathlib import Path

import click
from eth_typing import HexAddress

from src.common.config import VaultConfig
from src.common.language import LANGUAGES, create_new_mnemonic
from src.common.validators import validate_eth_address
from src.config.settings import AVAILABLE_NETWORKS, GOERLI


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='SW_DATA_DIR',
    help='Path where the vault data will be placed. Defaults to ~/.stakewise.',
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
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--network',
    default=GOERLI,
    help='The network of your vault.',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Initializes vault data directory and generates mnemonic.')
def init(
    language: str,
    no_verify: bool,
    vault: HexAddress,
    network: str,
    data_dir: str,
) -> None:
    config = VaultConfig(
        vault=vault,
        data_dir=Path(data_dir),
    )
    if config.vault_dir.exists():
        raise click.ClickException(f'Vault directory {config.vault_dir} already exists.')

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
            f'Successfully initialized configuration for vault {vault}', bold=True, fg='green'
        )
