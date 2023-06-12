import click
from eth_typing import HexAddress

from src.common.config import Config
from src.common.credentials import CredentialManager
from src.common.language import LANGUAGES, create_new_mnemonic
from src.common.validators import validate_eth_address
from src.config.settings import AVAILABLE_NETWORKS, GOERLI


@click.option(
    '--network',
    default=GOERLI,
    help='The network to generate the deposit data for.',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.option(
    '--language',
    default='english',
    prompt='Choose your mnemonic language.',
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
    '--no-verify',
    is_flag=True,
    help='Skips mnemonic verification when provided.',
)
@click.option(
    '--data-dir',
    required=False,
    help='Path where the vault data will be places. '
    'Defaults to ~/.stakewise/<vault>',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.command(help='Creates the mnemonic used to derive validator keys.')
def init(
    language: str,
    no_verify: bool,
    vault: HexAddress,
    network: str,
    data_dir: str,
) -> None:
    config = Config(
        data_dir=data_dir,
        vault=vault,
        network=network,
        mnemonic_next_index=0,
    )
    if config.data_dir.exists():
        raise click.ClickException(f'Vault directory {config.data_dir} already exists.')

    if not language:
        language = click.prompt(
            'Choose your mnemonic language',
            default='english',
            type=click.Choice(LANGUAGES, case_sensitive=False),
        )
    mnemonic = create_new_mnemonic(language, skip_test=no_verify)

    first_public_key = _get_first_public_key(network, vault, str(mnemonic))

    config.first_public_key = first_public_key
    config.create()
    if not no_verify:
        click.secho(
            f'Successfully initialized configuration for vault {vault}',
            bold=True,
            fg='green'
        )


def _get_first_public_key(network: str, vault: HexAddress, mnemonic: str) -> str:
    credential = CredentialManager.generate_credential(
        network=network,
        vault=vault,
        mnemonic=mnemonic,
        index=0,
    )

    return credential.public_key
