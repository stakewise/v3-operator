import itertools
import tempfile
from pathlib import Path

import click
from web3 import Web3

from src.config.env_vars import EnvVar, get_env_vars
from src.config.networks import MAINNET
from src.config.settings import settings

# Placeholders used to populate the settings singleton. The command never
# connects anywhere, it only needs `Settings.set()` to run so that the
# variables declared inside it register themselves. The variables are network
# agnostic, so the network is not worth exposing as an option.
PLACEHOLDER_VAULT = Web3.to_checksum_address('0x' + '00' * 20)
PLACEHOLDER_NETWORK = MAINNET


@click.option(
    '--format',
    'output_format',
    default='text',
    help='Output format. Use markdown to generate documentation.',
    type=click.Choice(['text', 'markdown'], case_sensitive=False),
)
@click.command(help='Lists the environment variables recognized by the operator.')
def env_vars(output_format: str) -> None:
    _load_settings()
    variables = get_env_vars()

    if output_format == 'markdown':
        _print_markdown(variables)
    else:
        _print_text(variables)


def _load_settings() -> None:
    """
    Populate the registry with the variables read inside `Settings.set()`.

    A temporary vault directory is used because `Settings.set()` creates it.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        settings.set(
            vault=PLACEHOLDER_VAULT,
            vault_dir=Path(tmp_dir),
            network=PLACEHOLDER_NETWORK,
        )


def _print_text(variables: list[EnvVar]) -> None:
    for group, group_vars in _grouped(variables):
        click.secho(f'\n{group}', bold=True)
        for var in group_vars:
            click.echo(f'  {click.style(var.name, fg="green")} ({var.type_name})')
            if var.description:
                click.echo(f'    {var.description}')
            click.echo(f'    Default: {var.formatted_default}')


def _print_markdown(variables: list[EnvVar]) -> None:
    for group, group_vars in _grouped(variables):
        click.echo(f'\n### {group}\n')
        click.echo('| Variable | Type | Default | Description |')
        click.echo('| --- | --- | --- | --- |')
        for var in group_vars:
            click.echo(
                f'| `{var.name}` | {var.type_name} '
                f'| `{var.formatted_default}` | {var.description} |'
            )


def _grouped(variables: list[EnvVar]) -> itertools.groupby:
    return itertools.groupby(variables, key=lambda var: var.group)
