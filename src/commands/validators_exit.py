import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import click
from aiohttp import ClientResponseError
from eth_typing import HexAddress, HexStr
from sw_utils import ValidatorStatus
from sw_utils.consensus import EXITED_STATUSES
from web3 import Web3

from src.common.clients import consensus_client
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import format_error, log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import AVAILABLE_NETWORKS, settings
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.load import load_keystore


@dataclass
class ValidatorExit:
    public_key: HexStr
    index: int


EXITING_STATUSES = [ValidatorStatus.ACTIVE_EXITING] + EXITED_STATUSES


@click.option(
    '--network',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
    envvar='NETWORK',
    help='The network of the vault. Default is the network specified at "init" command.',
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data is placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--count',
    help='The number of validators to exit.',
    type=click.IntRange(min=1),
)
@click.option(
    '--consensus-endpoints',
    help='Comma separated list of API endpoints for consensus nodes',
    prompt='Enter the comma separated list of API endpoints for consensus nodes',
    envvar='CONSENSUS_ENDPOINTS',
    type=str,
)
@click.option(
    '--remote-signer-url',
    type=str,
    envvar='REMOTE_SIGNER_URL',
    help='The base URL of the remote signer, e.g. http://signer:9000',
)
@click.option(
    '--hashi-vault-url',
    envvar='HASHI_VAULT_URL',
    help='The base URL of the vault service, e.g. http://vault:8200.',
)
@click.option(
    '--hashi-vault-token',
    envvar='HASHI_VAULT_TOKEN',
    help='Authentication token for accessing Hashi vault.',
)
@click.option(
    '--hashi-vault-key-path',
    envvar='HASHI_VAULT_KEY_PATH',
    help='Key path in the K/V secret engine where validator signing keys are stored.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
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
@click.command(help='Performs a voluntary exit for active vault validators.')
# pylint: disable-next=too-many-arguments
def validators_exit(
    network: str,
    vault: HexAddress,
    count: int | None,
    consensus_endpoints: str,
    remote_signer_url: str,
    hashi_vault_key_path: str | None,
    hashi_vault_token: str | None,
    hashi_vault_url: str | None,
    data_dir: str,
    verbose: bool,
    log_level: str,
) -> None:
    # pylint: disable=duplicate-code
    vault_config = VaultConfig(vault, Path(data_dir))
    if network is None:
        vault_config.load()
        network = vault_config.network

    settings.set(
        vault=vault,
        network=network,
        vault_dir=vault_config.vault_dir,
        consensus_endpoints=consensus_endpoints,
        remote_signer_url=remote_signer_url,
        hashi_vault_token=hashi_vault_token,
        hashi_vault_key_path=hashi_vault_key_path,
        hashi_vault_url=hashi_vault_url,
        verbose=verbose,
        log_level=log_level,
    )
    try:
        # Try-catch to enable async calls in test - an event loop
        #  will already be running in that case
        try:
            asyncio.get_running_loop()
            # we need to create a separate thread so we can block before returning
            with ThreadPoolExecutor(1) as pool:
                pool.submit(lambda: asyncio.run(main(count))).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(main(count))
            else:
                raise e
    except Exception as e:
        log_verbose(e)


async def main(count: int | None) -> None:
    setup_logging()
    keystore = await load_keystore()

    validators_exits = await _get_validators_exits(keystore=keystore)
    if not validators_exits:
        raise click.ClickException('There are no active validators.')

    validators_exits.sort(key=lambda x: x.index)

    if count:
        validators_exits = validators_exits[:count]

    click.confirm(
        f'Are you sure you want to exit {len(validators_exits)} validators '
        f'with indexes: {", ".join(str(x.index) for x in validators_exits)}?',
        abort=True,
    )
    exited_indexes = []
    for validator_exit in validators_exits:
        # todo: validatate that pk in keystores

        exit_signature = await keystore.get_exit_signature(
            validator_index=validator_exit.index,
            public_key=validator_exit.public_key,
        )
        try:
            await consensus_client.submit_voluntary_exit(
                validator_index=validator_exit.index,
                signature=Web3.to_hex(exit_signature),
                epoch=settings.network_config.SHAPELLA_FORK.epoch,
            )
        except ClientResponseError as e:
            # Validator status is updated in CL after some delay.
            # Status may be active in CL although validator has started exit process.
            # CL will return status 400 for exit request in this case.
            click.secho(
                f'{format_error(e)} for validator_index {validator_exit.index}',
                fg='yellow',
            )
            continue

        exited_indexes.append(validator_exit.index)

    if exited_indexes:
        click.secho(
            f'Validators {", ".join(str(index) for index in exited_indexes)} '
            f'({len(exited_indexes)} of {len(validators_exits)}) '
            f'exits successfully initiated',
            bold=True,
            fg='green',
        )


async def _get_validators_exits(
    keystore: BaseKeystore,
) -> list[ValidatorExit]:
    """Fetches validators consensus info."""
    public_keys = keystore.public_keys
    results = []
    exited_statuses = [x.value for x in EXITING_STATUSES]

    for i in range(0, len(public_keys), settings.validators_fetch_chunk_size):
        validators = await consensus_client.get_validators_by_ids(
            public_keys[i : i + settings.validators_fetch_chunk_size]
        )
        for beacon_validator in validators['data']:
            if beacon_validator.get('status') in exited_statuses:
                continue

            results.append(
                ValidatorExit(
                    public_key=beacon_validator['validator']['pubkey'],
                    index=int(beacon_validator['index']),
                )
            )
    return results
