import asyncio
import logging
import sys
from pathlib import Path
from typing import cast

import click
from eth_typing import ChecksumAddress, HexStr
from web3 import Web3
from web3.types import BlockNumber

from src.common.clients import execution_client, setup_clients
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import VaultContract
from src.common.execution import get_consolidation_request_fee, get_protocol_config
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import find_first, log_verbose
from src.common.validators import (
    validate_eth_address,
    validate_public_key,
    validate_public_keys,
    validate_public_keys_file,
)
from src.common.wallet import hot_wallet
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import (
    MAX_CONSOLIDATION_REQUEST_FEE,
    MAX_EFFECTIVE_BALANCE_GWEI,
    settings,
)
from src.validators.consensus import fetch_non_exiting_validators
from src.validators.oracles import poll_consolidation_signature
from src.validators.register_validators import submit_consolidate_validators
from src.validators.utils import load_public_keys

logger = logging.getLogger(__name__)


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
    help='Path where the config data is placed. Default is ~/.stakewise.',
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
    '--source-public-keys',
    type=HexStr,
    callback=validate_public_keys,
    help='Public keys of validators to consolidate from.',
)
@click.option(
    '--source-public-keys-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    callback=validate_public_keys_file,
    help='File with public keys of validators to consolidate from.',
)
@click.option(
    '--target-public-key',
    type=HexStr,
    callback=validate_public_key,
    help='Public key of validator to consolidate to.',
)
@click.option(
    '--consensus-endpoints',
    help='Comma separated list of API endpoints for consensus nodes',
    prompt='Enter the comma separated list of API endpoints for consensus nodes',
    envvar='CONSENSUS_ENDPOINTS',
    type=str,
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '--hot-wallet-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='HOT_WALLET_PASSWORD_FILE',
    help='Absolute path to the hot wallet password file. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--hot-wallet-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='HOT_WALLET_FILE',
    help='Absolute path to the hot wallet. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--no-confirm',
    is_flag=True,
    default=False,
    help='Skips confirmation messages when provided.',
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
@click.command(
    help='Performs a vault validators consolidation from 0x01 validators to 0x02 validator.'
)
# pylint: disable-next=too-many-arguments,too-many-locals
def consolidate(
    network: str,
    vault: ChecksumAddress,
    execution_endpoints: str,
    consensus_endpoints: str,
    data_dir: str,
    hot_wallet_file: str | None,
    hot_wallet_password_file: str | None,
    verbose: bool,
    no_confirm: bool,
    log_level: str,
    source_public_keys: list[HexStr] | None,
    source_public_keys_file: Path | None,
    target_public_key: HexStr,
) -> None:
    if all([source_public_keys, source_public_keys_file]):
        raise click.ClickException(
            'Provide only ony option: --from-public-keys-file or --from-public-keys.'
        )
    if not any([source_public_keys, source_public_keys_file]):
        raise click.ClickException(
            'Provide from public keys via one of options: '
            '--from-public-keys-file or --from-public-keys.'
        )

    if source_public_keys_file:
        source_public_keys = load_public_keys(source_public_keys_file)
    source_public_keys = cast(list[HexStr], source_public_keys)
    operator_config = OperatorConfig(Path(data_dir))
    operator_config.load(network=network)

    settings.set(
        vaults=[vault],
        network=operator_config.network,
        data_dir=operator_config.data_dir,
        execution_endpoints=execution_endpoints,
        consensus_endpoints=consensus_endpoints,
        hot_wallet_file=hot_wallet_file,
        hot_wallet_password_file=hot_wallet_password_file,
        verbose=verbose,
        log_level=log_level,
    )
    try:
        asyncio.run(
            main(
                vault_address=vault,
                source_public_keys=source_public_keys,
                target_public_key=target_public_key,
                no_confirm=no_confirm,
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    vault_address: ChecksumAddress,
    source_public_keys: list[HexStr],
    target_public_key: HexStr,
    no_confirm: bool,
) -> None:
    setup_logging()
    await setup_clients()
    await _check_validators_manager(vault_address)
    chain_head = await get_chain_finalized_head()

    target_source_public_keys = await _validate_public_keys(
        vault_address=vault_address,
        source_public_keys=source_public_keys,
        target_public_key=target_public_key,
        block_number=chain_head.block_number,
    )

    click.secho(
        f'Consolidating {len(target_source_public_keys)} validators: ',
    )
    for target_key, source_key in target_source_public_keys:
        click.secho(f'    {source_key} -> {target_key}')
    if not no_confirm:
        click.confirm(
            'Proceed consolidation?',
            default=True,
            abort=True,
        )

    current_fee = await get_consolidation_request_fee(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        block_number=await execution_client.eth.get_block_number(),
    )
    if current_fee > MAX_CONSOLIDATION_REQUEST_FEE:
        logger.info(
            'The current consolidation fee (%s Gwei) exceeds the maximum allowed (%s Gwei). '
            'You can override the limit using '
            'the MAX_CONSOLIDATION_REQUEST_FEE environment variable.',
            current_fee,
            MAX_CONSOLIDATION_REQUEST_FEE,
        )
        return
    protocol_config = await get_protocol_config()

    oracle_signatures = await poll_consolidation_signature(
        target_source_public_keys=target_source_public_keys,
        vault=vault_address,
        protocol_config=protocol_config,
    )

    encoded_validators = _encode_validators(target_source_public_keys)
    tx_hash = await submit_consolidate_validators(
        vault_address=vault_address,
        validators=encoded_validators,
        oracle_signatures=oracle_signatures,
        current_fee=current_fee,
    )

    if tx_hash:
        click.secho(
            'Validators have been successfully consolidated',
            bold=True,
            fg='green',
        )


async def _validate_public_keys(
    vault_address: ChecksumAddress,
    source_public_keys: list[HexStr],
    target_public_key: HexStr,
    block_number: BlockNumber,
) -> list[tuple[HexStr, HexStr]]:
    """Validate that provided public keys can be consolidated."""
    logger.info('Checking selected validators for consolidation...')
    all_public_keys = source_public_keys + [target_public_key]
    active_validators = await fetch_non_exiting_validators(source_public_keys + [target_public_key])
    active_public_keys = {key.public_key for key in active_validators}
    non_active_public_keys = set(all_public_keys) - active_public_keys
    for key in non_active_public_keys:
        raise click.ClickException(f'Trying to consolidate non-active validator {key}.')

    # validate that target_public_key is a compounding validator.
    # Not required for a single validator consolidation
    if not _is_switch_to_compounding(source_public_keys, target_public_key):
        target_validator = find_first(
            active_validators, lambda val: val.public_key == target_public_key
        )
        if target_validator and not target_validator.is_compounding:
            raise click.ClickException(
                f'The target validator {target_public_key} is not a compounding validator.'
            )

    logger.info('Fetching vault validators...')
    vault_validators = await VaultContract(vault_address).get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=block_number,
    )
    for public_keys in source_public_keys + [target_public_key]:
        if public_keys not in vault_validators:
            raise click.ClickException(
                f'Validator {public_keys} is not registered in the vault {vault_address}.'
            )
    if sum(val.balance for val in active_validators) > MAX_EFFECTIVE_BALANCE_GWEI:
        raise click.ClickException(
            'Cannot consolidate validators,'
            f' total balance exceed {MAX_EFFECTIVE_BALANCE_GWEI} Gwei'
        )

    return [(target_public_key, source_key) for source_key in source_public_keys]


def _encode_validators(target_source_public_keys: list[tuple[HexStr, HexStr]]) -> bytes:
    validators_data = b''
    for target_key, source_key in target_source_public_keys:
        validators_data += Web3.to_bytes(hexstr=source_key)
        validators_data += Web3.to_bytes(hexstr=target_key)
    return validators_data


async def _check_validators_manager(vault_address: ChecksumAddress) -> None:
    vault_contract = VaultContract(vault_address)
    validators_manager = await vault_contract.validators_manager()
    if validators_manager != hot_wallet.account.address:
        raise RuntimeError('validators manager address must equal to hot wallet address')


def _is_switch_to_compounding(source_public_keys: list[HexStr], target_public_key: HexStr) -> bool:
    return len(source_public_keys) == 1 and source_public_keys[0] == target_public_key
