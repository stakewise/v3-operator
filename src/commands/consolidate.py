import asyncio
import logging
import math
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress, HexStr
from web3 import Web3

from src.common.clients import execution_client, setup_clients
from src.common.consensus import (
    fetch_v1_registered_validators,
    get_chain_finalized_head,
)
from src.common.contracts import VaultContract
from src.common.execution import get_protocol_config, get_request_fee
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.typings import ConsensusValidator
from src.common.utils import format_error, log_verbose
from src.common.validators import validate_eth_address
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import (
    MAX_CONSOLIDATION_REQUEST_FEE,
    PECTRA_MAX_EFFECTIVE_BALANCE_GWEI,
    settings,
)
from src.validators.oracles import poll_consolidation_signature
from src.validators.validators_manager import (
    get_validators_manager_signature_consolidation,
)

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
) -> None:
    vault_config = OperatorConfig(Path(data_dir))
    if network is None:
        vault_config.load()
        network = vault_config.network

    settings.set(
        vaults=[vault],
        network=network,
        config_dir=vault_config.config_dir,
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
                no_confirm=no_confirm,
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(vault_address: ChecksumAddress, count: int | None, no_confirm: bool) -> None:
    setup_logging()
    await setup_clients()

    validators = await fetch_v1_registered_validators(vault_address)
    # filter active?
    if not validators:
        raise click.ClickException(f'No registered validators for vault {vault_address}')
    if len(validators) == 1:
        raise click.ClickException('Single validator cannot be consolidated')

    chain_head = await get_chain_finalized_head()
    current_fee = await get_request_fee(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS, block_number=chain_head.block_number
    )
    if current_fee > MAX_CONSOLIDATION_REQUEST_FEE:
        logger.info(
            'Consolidation is skipped because high consolidation fee, current fees is %s. '
            'Increase MAX_CONSOLIDATION_REQUEST_FEE env var to allow it',
            current_fee,
        )
        return
    source_target_public_keys = _split_validators(validators)
    if count is not None:
        source_target_public_keys = source_target_public_keys[:count]

    click.secho(
        f'Vault has {len(validators)} registered validator(s), ' f'Consolidating next validators: ',
    )
    for from_key, to_key in source_target_public_keys:
        click.secho(f'    {from_key} -> {to_key}')
    if not no_confirm:
        click.confirm(
            'Proceed consolidation?',
            default=True,
            abort=True,
        )

    protocol_config = await get_protocol_config()

    oracle_signatures = await poll_consolidation_signature(
        source_target_public_keys=source_target_public_keys,
        vault=vault_address,
        protocol_config=protocol_config,
    )
    # get validatorsManagerSignature
    encoded_validators = _encode_validators(source_target_public_keys)
    validators_manager_signature = get_validators_manager_signature_consolidation(
        vault=vault_address,
        encoded_validators=encoded_validators,
    )
    tx_hash = await submit_consolidate_validators(
        validators=encoded_validators,
        validators_manager_signature=Web3.to_bytes(hexstr=validators_manager_signature),
        oracle_signatures=oracle_signatures,
    )

    if tx_hash:
        click.secho(
            'Validators has been successfully consolidated',
            bold=True,
            fg='green',
        )


def _split_validators(validators: list[ConsensusValidator]) -> list[tuple[HexStr, HexStr]]:
    """
    Return list of tuples with public keys of validators to be consolidated.
    Format [(target_public_key, source_public_key), ...]
    """
    total_balance = sum(x.balance for x in validators)
    target_validators_count = math.ceil(total_balance / PECTRA_MAX_EFFECTIVE_BALANCE_GWEI)
    target_validators = validators[:target_validators_count]
    source_validators = validators[target_validators_count:]

    source_target_public_keys = []
    current_target_index = 0
    for validator in source_validators:
        current_target_validator = target_validators[current_target_index]
        if (
            validator.balance + current_target_validator.balance
            <= PECTRA_MAX_EFFECTIVE_BALANCE_GWEI
        ):
            current_target_validator.balance += validator.balance
            source_target_public_keys.append(
                (current_target_validator.public_key, validator.public_key)
            )
        else:
            current_target_index += 1
            current_target_validator = target_validators[current_target_index]
            current_target_validator.balance += validator.balance
            source_target_public_keys.append(
                (current_target_validator.public_key, validator.public_key)
            )

    return source_target_public_keys


def _encode_validators(from_to_public_keys: list[tuple[HexStr, HexStr]]) -> bytes:
    validators_data = b''
    for from_key, to_key in from_to_public_keys:
        validators_data += Web3.to_bytes(hexstr=from_key)
        validators_data += Web3.to_bytes(hexstr=to_key)
    return validators_data


async def submit_consolidate_validators(
    validators: bytes,
    validators_manager_signature: bytes,
    oracle_signatures: bytes,
) -> HexStr | None:
    """Sends consolidateValidators transaction to vault contract"""
    logger.info('Submitting consolidateValidators transaction')
    vault_contract = VaultContract(settings.vaults[0])
    try:
        tx = await vault_contract.functions.consolidateValidators(
            validators,
            validators_manager_signature,
            oracle_signatures,
        ).transact()
    except Exception as e:
        logger.info('Failed to update exit signatures: %s', format_error(e))
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.info('UpdateExitSignatures transaction failed')
        return None
    return Web3.to_hex(tx)
