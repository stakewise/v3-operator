import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress, HexStr
from web3 import Web3
from web3.types import BlockNumber, Gwei

from src.common.clients import execution_client, setup_clients
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import VaultContract
from src.common.execution import get_protocol_config, get_request_fee
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import format_error, log_verbose
from src.common.validators import (
    validate_eth_address,
    validate_public_key,
    validate_public_keys,
)
from src.common.wallet import hot_wallet
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import (
    MAX_CONSOLIDATION_REQUEST_FEE,
    MAX_EFFECTIVE_BALANCE_GWEI,
    settings,
)
from src.validators.consensus import fetch_active_validators_balances
from src.validators.oracles import poll_consolidation_signature

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
    '--count',
    help='The maximum number of validators to consolidate.',
    type=click.IntRange(min=1),
    default=None,
)
@click.option(
    '--from-keys',
    type=list[HexStr],
    callback=validate_public_keys,
    help='Public keys of validators to consolidate from.',
)
@click.option(
    '--to-key',
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
@click.command(help='Performs a vault validators consolidation after pectra upgrade.')
# pylint: disable-next=too-many-arguments,too-many-locals
def consolidate(
    network: str,
    vault: ChecksumAddress,
    execution_endpoints: str,
    consensus_endpoints: str,
    data_dir: str,
    verbose: bool,
    no_confirm: bool,
    log_level: str,
    count: int | None = None,
    from_keys: list[HexStr] | None = None,
    to_key: HexStr | None = None,
) -> None:
    operator_config = OperatorConfig(Path(data_dir))
    if network is None:
        operator_config.load()
        network = operator_config.network

    settings.set(
        vaults=[vault],
        network=network,
        data_dir=operator_config.data_dir,
        execution_endpoints=execution_endpoints,
        consensus_endpoints=consensus_endpoints,
        verbose=verbose,
        log_level=log_level,
    )
    try:
        asyncio.run(
            main(
                vault_address=vault,
                count=count,
                from_keys=from_keys,
                to_key=to_key,
                no_confirm=no_confirm,
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    vault_address: ChecksumAddress,
    count: int | None,
    from_keys: list[HexStr] | None,
    to_key: HexStr | None,
    no_confirm: bool,
) -> None:
    setup_logging()
    await setup_clients()
    await _check_validators_manager()
    chain_head = await get_chain_finalized_head()

    if from_keys is not None and to_key is not None:
        target_source_public_keys = await _get_selected_target_source_public_keys(
            from_keys=from_keys,
            to_key=to_key,
        )

    else:
        target_source_public_keys = await _get_all_target_source_public_keys(
            vault_address=vault_address,
            block_number=chain_head.block_number,
            count=count,
        )

    click.secho(
        'Consolidating next validators: ',
    )
    for target_key, source_key in target_source_public_keys:
        click.secho(f'    {source_key} -> {target_key}')
    if not no_confirm:
        click.confirm(
            'Proceed consolidation?',
            default=True,
            abort=True,
        )
    current_fee = await get_request_fee(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS, block_number=chain_head.block_number
    )
    if current_fee > MAX_CONSOLIDATION_REQUEST_FEE:
        logger.info(
            'Consolidation is skipped because high consolidation fee, current fees is %s. '
            'Increase MAX_CONSOLIDATION_REQUEST_FEE env var to allow it',
            current_fee,
        )
        return
    protocol_config = await get_protocol_config()

    oracle_signatures = await poll_consolidation_signature(
        target_source_public_keys=target_source_public_keys,
        vault=vault_address,
        protocol_config=protocol_config,
    )

    encoded_validators = _encode_validators(target_source_public_keys)
    tx_hash = await _submit_consolidate_validators(
        validators=encoded_validators,
        oracle_signatures=oracle_signatures,
        current_fee=current_fee,
    )

    if tx_hash:
        click.secho(
            'Validators has been successfully consolidated',
            bold=True,
            fg='green',
        )


async def _get_all_target_source_public_keys(
    vault_address: ChecksumAddress, block_number: BlockNumber, count: int | None = None
) -> list[tuple[HexStr, HexStr]]:
    """
    Fetch all available public keys pairs for consolidation.
    Can be limited via count parameter.
    """
    vault_contract = VaultContract(vault_address)
    public_keys = await vault_contract.get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=block_number,
    )
    active_balances = await fetch_active_validators_balances(public_keys)
    if not active_balances or len(active_balances) < 2:
        raise click.ClickException(
            f'Not enough active validators for vault {vault_address} to consolidate'
        )

    source_target_public_keys = _split_validators(active_balances)
    if count is not None:
        source_target_public_keys = source_target_public_keys[:count]
    return source_target_public_keys


async def _get_selected_target_source_public_keys(
    from_keys: list[HexStr],
    to_key: HexStr,
) -> list[tuple[HexStr, HexStr]]:
    """Validate that provided public keys can be consolidated."""
    active_balances = await fetch_active_validators_balances(from_keys + [to_key])
    for key in from_keys + [to_key]:
        if key not in active_balances:
            raise click.ClickException(f'Trying to consolidate non-active validator {key}.')

    if not sum(active_balances.values()):
        raise click.ClickException(
            'Cannot consolidate validators,'
            f' total balance exceed {MAX_EFFECTIVE_BALANCE_GWEI} Gwei'
        )

    return [(from_key, to_key) for from_key in from_keys]


def _split_validators(validators: dict[HexStr, Gwei]) -> list[tuple[HexStr, HexStr]]:
    """
    Return list of tuples with public keys of validators to be consolidated.
    Format [(target_public_key, source_public_key), ...]
    """
    source_target_public_keys = []
    used_keys = set()
    for target_public_key, target_balance in sorted(
        validators.items(), key=lambda item: item[1], reverse=True
    ):
        if target_public_key in used_keys:
            break
        for source_public_key, source_balance in sorted(
            validators.items(), key=lambda item: item[1], reverse=False
        ):
            if source_public_key == target_public_key or source_public_key in used_keys:
                continue

            if target_balance + source_balance > MAX_EFFECTIVE_BALANCE_GWEI:
                break
            target_balance = Gwei(target_balance + source_balance)
            source_target_public_keys.append((target_public_key, source_public_key))
            used_keys.add(target_public_key)
            used_keys.add(source_public_key)
    return source_target_public_keys


def _encode_validators(target_source_public_keys: list[tuple[HexStr, HexStr]]) -> bytes:
    validators_data = b''
    for to_key, from_key in target_source_public_keys:
        validators_data += Web3.to_bytes(hexstr=from_key)
        validators_data += Web3.to_bytes(hexstr=to_key)
    return validators_data


async def _submit_consolidate_validators(
    validators: bytes,
    oracle_signatures: bytes,
    current_fee: Gwei,
) -> HexStr | None:
    """Sends consolidate validators transaction to vault contract"""
    logger.info('Submitting consolidate validators transaction')
    vault_contract = VaultContract(settings.vaults[0])
    try:
        tx = await vault_contract.functions.consolidateValidators(
            validators,
            b'',
            oracle_signatures,
        ).transact({'value': Web3.to_wei(current_fee, 'gwei')})
    except Exception as e:
        logger.info('Failed to submit consolidate validators transaction: %s', format_error(e))
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.info('Consolidate validators transaction failed')
        return None
    return Web3.to_hex(tx)


async def _check_validators_manager() -> None:
    vault_address = settings.vaults[0]
    vault_contract = VaultContract(vault_address)
    validators_manager = await vault_contract.validators_manager()
    if validators_manager != hot_wallet.account.address:
        raise RuntimeError('validators manager address must equal to hot wallet address')
