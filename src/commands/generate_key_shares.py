import asyncio
import logging
import os
from pathlib import Path

import click
import milagro_bls_binding as bls
from eth_typing import BLSPrivateKey, HexAddress
from web3 import Web3

from src.commands.create_keys import _export_keystores
from src.common.credentials import Credential
from src.common.execution import get_oracles
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import settings
from src.validators.signing.key_shares import private_key_to_private_key_shares
from src.validators.signing.remote import RemoteSignerConfiguration
from src.validators.utils import load_keystores

logger = logging.getLogger(__name__)


@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(file_okay=False, dir_okay=True),
)
@click.option(
    '--keystores-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='KEYSTORES_DIR',
    help='Absolute path to the directory with all the encrypted keystores. '
    'Default is the directory generated with "create-keys" command.',
)
@click.option(
    '--output-dir',
    type=click.Path(file_okay=False),
    required=True,
    help='Absolute path to the directory where the output keystore shares should be placed.',
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.command(help='Generates private key shares to be uploaded to a remote signer.')
# pylint: disable-next=too-many-arguments
def generate_key_shares(
    vault: HexAddress,
    data_dir: str,
    keystores_dir: str | None,
    output_dir: str,
    execution_endpoints: str,
    verbose: bool,
) -> None:
    config = VaultConfig(vault, Path(data_dir))
    config.load()
    settings.set(
        vault=vault,
        vault_dir=config.vault_dir,
        network=config.network,
        execution_endpoints=execution_endpoints,
        keystores_dir=keystores_dir,
        verbose=verbose,
    )

    try:
        asyncio.run(main(output_dir=Path(output_dir)))
    except Exception as e:
        log_verbose(e)


async def main(output_dir: Path) -> None:
    keystores = load_keystores()

    if len(keystores) == 0:
        raise click.ClickException('Keystores not found.')

    oracles = await get_oracles()

    try:
        remote_signer_config = RemoteSignerConfiguration.from_file(
            settings.remote_signer_config_file
        )
    except FileNotFoundError:
        remote_signer_config = RemoteSignerConfiguration(pubkeys_to_shares={})

    credentials = []
    for pubkey, private_key in keystores.items():  # pylint: disable=no-member
        private_key_shares = private_key_to_private_key_shares(
            private_key=private_key,
            threshold=oracles.exit_signature_recover_threshold,
            total=len(oracles.public_keys),
        )

        for idx, private_key_share in enumerate(private_key_shares):
            credentials.append(
                Credential(
                    private_key=BLSPrivateKey(int.from_bytes(private_key_share, 'big')),
                    path=f'share_{pubkey}_{idx}',
                    network=settings.network,
                    vault=settings.vault,
                )
            )
        remote_signer_config.pubkeys_to_shares[pubkey] = [
            Web3.to_hex(bls.SkToPk(priv_key)) for priv_key in private_key_shares
        ]

    _export_keystores(
        credentials=credentials,
        keystores_dir=output_dir,
        password_file=str(settings.keystores_password_file),
        per_keystore_password=False,
    )

    click.echo(
        f'Successfully generated {len(credentials)} key shares'
        f' for {len(keystores)} private key(s)!',
    )

    # Remove local keystores - remote signer will be used
    for keystore_file in os.listdir(settings.keystores_dir):
        if not keystore_file.startswith('keystore-'):
            continue
        os.remove(settings.keystores_dir / keystore_file)

    click.echo(
        'Removed local keystores.',
    )

    remote_signer_config.save(settings.remote_signer_config_file)

    click.echo(
        f'Done.'
        f' Successfully configured operator to use remote signer'
        f' for {len(keystores)} public key(s)!',
    )
