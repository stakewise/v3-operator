import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import click
from aiohttp import ClientResponseError
from eth_typing import HexStr
from sw_utils import ValidatorStatus
from sw_utils.consensus import EXITED_STATUSES
from web3 import Web3

from src.common.clients import consensus_client
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import format_error, log_verbose
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import (
    DEFAULT_HASHI_VAULT_ENGINE_NAME,
    DEFAULT_HASHI_VAULT_PARALLELISM,
    settings,
)
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
    '--hashi-vault-engine-name',
    envvar='HASHI_VAULT_ENGINE_NAME',
    help='The name of the secret engine, e.g. keystores',
    default=DEFAULT_HASHI_VAULT_ENGINE_NAME,
)
@click.option(
    '--hashi-vault-token',
    envvar='HASHI_VAULT_TOKEN',
    help='Authentication token for accessing Hashi vault.',
)
@click.option(
    '--hashi-vault-key-path',
    multiple=True,
    envvar='HASHI_VAULT_KEY_PATH',
    help='Key path in the K/V secret engine where validator signing keys are stored.',
)
@click.option(
    '--hashi-vault-key-prefix',
    envvar='HASHI_VAULT_KEY_PREFIX',
    multiple=True,
    help='Key prefix(es) in the K/V secret engine under which validator signing keys are stored.',
)
@click.option(
    '--hashi-vault-parallelism',
    envvar='HASHI_VAULT_PARALLELISM',
    help='How much requests to K/V secrets engine to do in parallel.',
    default=DEFAULT_HASHI_VAULT_PARALLELISM,
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
@click.option(
    '--pool-size',
    help='Number of processes in a pool.',
    envvar='POOL_SIZE',
    type=int,
)
@click.command(help='Performs a voluntary exit for active vault validators.')
# pylint: disable-next=too-many-arguments,too-many-locals
def validators_exit(
    network: str,
    count: int | None,
    consensus_endpoints: str,
    remote_signer_url: str,
    hashi_vault_key_path: list[str] | None,
    hashi_vault_key_prefix: list[str] | None,
    hashi_vault_token: str | None,
    hashi_vault_url: str | None,
    hashi_vault_engine_name: str,
    hashi_vault_parallelism: int,
    data_dir: str,
    verbose: bool,
    log_level: str,
    pool_size: int | None,
) -> None:
    # pylint: disable=duplicate-code
    vault_config = OperatorConfig(Path(data_dir))
    if network is None:
        vault_config.load()
        network = vault_config.network

    settings.set(
        vaults=[],
        network=network,
        config_dir=vault_config.config_dir,
        consensus_endpoints=consensus_endpoints,
        remote_signer_url=remote_signer_url,
        hashi_vault_token=hashi_vault_token,
        hashi_vault_key_paths=hashi_vault_key_path,
        hashi_vault_key_prefixes=hashi_vault_key_prefix,
        hashi_vault_url=hashi_vault_url,
        hashi_vault_engine_name=hashi_vault_engine_name,
        hashi_vault_parallelism=hashi_vault_parallelism,
        verbose=verbose,
        log_level=log_level,
        pool_size=pool_size,
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
        sys.exit(1)


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
        f'with indexes: {', '.join(str(x.index) for x in validators_exits)}?',
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
            f'Validators {', '.join(str(index) for index in exited_indexes)} '
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
