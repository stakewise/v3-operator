import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import click
from eth_typing import HexAddress
from eth_utils import add_0x_prefix
from tqdm import tqdm
from web3.types import HexStr

from src.commands.validators_exit import EXITING_STATUSES
from src.common.clients import consensus_client, execution_client
from src.common.contracts import vault_contract
from src.common.credentials import CredentialManager
from src.common.password import generate_password, get_or_create_password_file
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address, validate_mnemonic
from src.common.vault_config import VaultConfig
from src.config.settings import AVAILABLE_NETWORKS, GOERLI, settings


@dataclass
class RegisteredValidator:
    index: int
    public_key: HexStr
    status: str
    keystore_found: bool = field(default=False)


@click.command(help='Recover vault data directory and keystores.')
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.option(
    '--per-keystore-password',
    is_flag=True,
    default=False,
    help='Creates separate password file for each keystore.',
)
@click.option(
    '--mnemonic',
    help='The mnemonic for generating the validator keys.',
    prompt='Enter the mnemonic for generating the validator keys',
    type=str,
    callback=validate_mnemonic,
)
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '--consensus-endpoints',
    type=str,
    envvar='CONSENSUS_ENDPOINTS',
    prompt='Enter comma separated list of API endpoints for consensus nodes',
    help='Comma separated list of API endpoints for consensus nodes.',
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
# pylint: disable-next=too-many-arguments
def recover(
    data_dir: str,
    vault: HexAddress,
    network: str,
    mnemonic: str,
    consensus_endpoints: str,
    execution_endpoints: str,
    per_keystore_password: bool,
) -> None:
    # pylint: disable=duplicate-code
    config = VaultConfig(
        vault=vault,
        data_dir=Path(data_dir),
    )
    if config.vault_dir.exists():
        raise click.ClickException(f'Vault directory {config.vault_dir} already exists.')

    keystores_dir = config.vault_dir / 'keystores'
    password_file = keystores_dir / 'password.txt'

    settings.set(
        execution_endpoints=execution_endpoints,
        consensus_endpoints=consensus_endpoints,
        vault=vault,
        network=network,
        vault_dir=Path(data_dir, vault),
    )

    try:
        asyncio.run(
            main(
                mnemonic,
                keystores_dir,
                password_file,
                per_keystore_password,
                config,
            )
        )
    except Exception as e:
        log_verbose(e)


# pylint: disable-next=too-many-arguments
async def main(
    mnemonic: str,
    keystores_dir: Path,
    password_file: Path,
    per_keystore_password: bool,
    config: VaultConfig,
):
    validators = await _fetch_registered_validators()
    if not validators:
        raise click.ClickException('No registered validators')
    click.secho(f'Found {len(validators)} validators, recovering...')

    mnemonic_next_index = await _generate_keystores(
        mnemonic,
        keystores_dir,
        password_file,
        validators,
        per_keystore_password,
    )

    config.save(settings.network, mnemonic, mnemonic_next_index)
    click.secho(
        f'Keystores for vault {settings.vault} successfully recovered', bold=True, fg='green'
    )


# pylint: disable-next=too-many-locals
async def _fetch_registered_validators() -> list[RegisteredValidator]:
    """Fetch registered validators."""
    block = await execution_client.eth.get_block('latest')
    current_block = block['number']
    keeper_genesis_block = settings.network_config.KEEPER_GENESIS_BLOCK

    page_size = 50_000
    public_keys = []

    for cursor in range(keeper_genesis_block, current_block, page_size):
        page_start = cursor
        page_end = min(cursor + page_size - 1, current_block)

        events = await vault_contract.events.ValidatorRegistered.get_logs(
            fromBlock=page_start, toBlock=page_end
        )
        for event in events:
            hex_key = event['args']['publicKey'].hex()
            public_keys.append(add_0x_prefix(hex_key))

    results = []

    for i in range(0, len(public_keys), settings.validators_fetch_chunk_size):
        validators = await consensus_client.get_validators_by_ids(
            public_keys[i : i + settings.validators_fetch_chunk_size]
        )
        for beacon_validator in validators['data']:
            results.append(
                RegisteredValidator(
                    index=beacon_validator['index'],
                    public_key=beacon_validator['validator']['pubkey'],
                    status=beacon_validator['status'],
                )
            )

    return results


# pylint: disable-next=too-many-arguments,too-many-locals
async def _generate_keystores(
    mnemonic: str,
    keystores_dir: Path,
    password_file: Path,
    validators: list[RegisteredValidator],
    per_keystore_password: bool,
):
    keystores_dir.mkdir(parents=True, exist_ok=True)
    exited_statuses = [x.value for x in EXITING_STATUSES]

    validators_dict = {add_0x_prefix(validator.public_key): validator for validator in validators}
    total_validators = len(validators_dict)

    progress_bar = tqdm(total=total_validators, dynamic_ncols=True)

    index = 0
    failed_attempts = 0

    while total_validators > 0:
        credential = CredentialManager.generate_credential(
            network=settings.network,
            vault=settings.vault,
            mnemonic=mnemonic,
            index=index,
        )

        # Check the current public key against the dict
        public_key = add_0x_prefix(credential.public_key)
        if public_key in validators_dict:
            validator = validators_dict.pop(public_key)
            total_validators -= 1
            progress_bar.update(1)

            if validator.status not in exited_statuses:
                password = (
                    generate_password()
                    if per_keystore_password
                    else get_or_create_password_file(str(password_file))
                )
                credential.save_signing_keystore(
                    password, str(keystores_dir), per_keystore_password
                )
            failed_attempts = 0
        else:
            failed_attempts += 1

        if failed_attempts > 100:
            progress_bar.close()
            raise click.ClickException('Keystores not found, check mnemonic')

        index += 1

    progress_bar.close()
    return index
