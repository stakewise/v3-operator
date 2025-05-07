import asyncio
import sys
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils.consensus import EXITED_STATUSES, ValidatorStatus

from src.common.clients import consensus_client, execution_client, setup_clients
from src.common.contracts import VaultContract, v2_pool_contract
from src.common.credentials import CredentialManager
from src.common.execution import SECONDS_PER_MONTH
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.password import generate_password, get_or_create_password_file
from src.common.utils import greenify, log_verbose
from src.common.validators import validate_eth_addresses, validate_mnemonic
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import DEFAULT_NETWORK, settings


@click.command(help='Recover config data directory and keystores.')
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the config data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.option(
    '--per-keystore-password',
    is_flag=True,
    default=False,
    help='Creates separate password file for each keystore.',
)
@click.option(
    '--no-confirm',
    is_flag=True,
    default=False,
    help='Skips confirmation messages when provided.',
)
@click.option(
    '--mnemonic',
    help='The mnemonic for generating the validator keys.',
    prompt='Enter the mnemonic for generating the validator keys',
    type=str,
    hide_input=True,
    callback=validate_mnemonic,
)
@click.option(
    '--vaults',
    prompt='Enter comma separated list of your vault addresses',
    help='Vault addresses',
    type=str,
    callback=validate_eth_addresses,
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
    default=DEFAULT_NETWORK,
    help='The network of your vault.',
    prompt='Enter the network name',
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
# pylint: disable-next=too-many-arguments
def recover(
    data_dir: str,
    vaults: list[ChecksumAddress],
    network: str,
    mnemonic: str,
    consensus_endpoints: str,
    execution_endpoints: str,
    per_keystore_password: bool,
    no_confirm: bool,
    log_level: str,
) -> None:
    # pylint: disable=duplicate-code
    config = OperatorConfig(
        Path(data_dir),
    )
    if not config.config_dir.exists():
        # create vault dir if it does not exist
        config.config_dir.mkdir(parents=True)
        click.secho(f'Vault directory {config.config_dir} created.', bold=True, fg='green')

    keystores_dir = config.config_dir / 'keystores'
    password_file = keystores_dir / 'password.txt'

    settings.set(
        execution_endpoints=execution_endpoints,
        consensus_endpoints=consensus_endpoints,
        vaults=vaults,
        network=network,
        config_dir=config.config_dir,
        log_level=log_level,
    )

    try:
        asyncio.run(
            main(
                mnemonic=mnemonic,
                keystores_dir=keystores_dir,
                password_file=password_file,
                per_keystore_password=per_keystore_password,
                no_confirm=no_confirm,
                config=config,
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


# pylint: disable-next=too-many-arguments
async def main(
    mnemonic: str,
    keystores_dir: Path,
    password_file: Path,
    per_keystore_password: bool,
    no_confirm: bool,
    config: OperatorConfig,
) -> None:
    setup_logging()
    await setup_clients()

    validators: dict[HexStr, ValidatorStatus | None] = {}
    for vault in settings.vaults:
        vault_validators = await _fetch_registered_validators(vault)
        validators = validators | vault_validators

    if not validators:
        raise click.ClickException('No registered validators')

    total_validators = len(validators)
    if no_confirm:
        click.secho(
            f'Vault has {total_validators} registered validator(s), '
            f'recovering active keystores from provided mnemonic...',
        )
    else:
        click.confirm(
            f'Vault has {total_validators} registered validator(s), '
            f'recover active keystores from provided mnemonic?',
            default=True,
            abort=True,
        )

    if keystores_dir.exists():
        if no_confirm:
            click.secho(f'Removing existing {keystores_dir} keystores directory...')
        else:
            click.confirm(
                f'Remove existing {keystores_dir} keystores directory?',
                default=True,
                abort=True,
            )
        for file in keystores_dir.glob('*'):
            file.unlink()
    else:
        keystores_dir.mkdir(parents=True)

    mnemonic_next_index = await _generate_keystores(
        mnemonic=mnemonic,
        keystores_dir=keystores_dir,
        password_file=password_file,
        validator_statuses=validators,
        per_keystore_password=per_keystore_password,
    )

    config.save(settings.network, mnemonic, mnemonic_next_index)
    click.secho(
        f'Successfully recovered {greenify(mnemonic_next_index)} '
        f'keystores for vaults {greenify(settings.vaults)}',
    )


# pylint: disable-next=too-many-locals
async def _fetch_registered_validators(
    vault: ChecksumAddress,
) -> dict[HexStr, ValidatorStatus | None]:
    """Fetch registered validators."""
    click.secho(f'Fetching registered validators for vault {vault}...', bold=True)
    current_block = await execution_client.eth.get_block_number()
    vault_contract = VaultContract(vault)
    public_keys = await vault_contract.get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=current_block,
    )

    if (
        settings.network_config.IS_SUPPORT_V2_MIGRATION
        and vault == settings.network_config.GENESIS_VAULT_CONTRACT_ADDRESS
    ):
        # fetch registered validators from v2 pool contract
        # new validators won't be registered after upgrade to the v3,
        # no need to check up to the latest block
        blocks_per_month = int(SECONDS_PER_MONTH // settings.network_config.SECONDS_PER_BLOCK)
        to_block = BlockNumber(
            min(
                settings.network_config.KEEPER_GENESIS_BLOCK + blocks_per_month,
                current_block,
            )
        )
        public_keys.extend(
            await v2_pool_contract.get_registered_validators_public_keys(
                from_block=settings.network_config.V2_POOL_GENESIS_BLOCK, to_block=to_block
            )
        )
    click.secho(f'Fetched {len(public_keys)} registered validators', bold=True)

    click.secho('Fetching validators statuses...', bold=True)
    validator_statuses: dict[HexStr, ValidatorStatus | None] = {
        public_key: None for public_key in public_keys
    }
    for i in range(0, len(public_keys), settings.validators_fetch_chunk_size):
        validators = await consensus_client.get_validators_by_ids(
            public_keys[i : i + settings.validators_fetch_chunk_size]
        )
        for beacon_validator in validators['data']:
            public_key = add_0x_prefix(beacon_validator['validator']['pubkey'])
            validator_statuses[public_key] = ValidatorStatus(beacon_validator['status'])
    click.secho('Fetched statuses for registered validators', bold=True)

    return validator_statuses


# pylint: disable-next=too-many-arguments,too-many-locals
async def _generate_keystores(
    mnemonic: str,
    keystores_dir: Path,
    password_file: Path,
    validator_statuses: dict[HexStr, ValidatorStatus | None],
    per_keystore_password: bool,
) -> int:
    index = 0
    failed_attempts = 0

    validators_count = len(validator_statuses)
    # stop once failed 1000 times
    while failed_attempts != 1000:
        # generate credential
        credential = CredentialManager.generate_credential(
            network=settings.network,
            mnemonic=mnemonic,
            index=index,
        )
        public_key = add_0x_prefix(credential.public_key)
        # increase index for next iteration
        index += 1

        # check whether public key is registered
        if public_key not in validator_statuses:
            failed_attempts += 1
            continue

        # get validator status
        validator_status = validator_statuses.pop(public_key)
        validators_count -= 1

        # update progress, reset failed attempts
        failed_attempts = 0

        # skip if validator is already exited
        if validator_status in EXITED_STATUSES:
            continue

        # generate password and save keystore
        password = (
            generate_password()
            if per_keystore_password
            else get_or_create_password_file(password_file)
        )
        credential.save_signing_keystore(password, str(keystores_dir), per_keystore_password)
        click.secho(
            f'Keystore for validator {greenify(public_key)} successfully '
            f'recovered from mnemonic index {greenify(index - 1)}',
        )

    return index - failed_attempts
