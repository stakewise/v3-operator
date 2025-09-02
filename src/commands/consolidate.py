import asyncio
import logging
import sys
from pathlib import Path
from typing import cast

import click
from eth_typing import ChecksumAddress, HexStr
from sw_utils import ChainHead
from web3 import Web3
from web3.types import Gwei

from src.common.clients import consensus_client, setup_clients
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import VaultContract
from src.common.execution import (
    build_gas_manager,
    get_execution_request_fee,
    get_protocol_config,
)
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import find_first, log_verbose
from src.common.validators import (
    validate_eth_address,
    validate_public_key,
    validate_public_keys,
    validate_public_keys_file,
)
from src.common.wallet import wallet
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import (
    MAX_CONSOLIDATION_REQUEST_FEE,
    MAX_EFFECTIVE_BALANCE_GWEI,
    settings,
)
from src.validators.consensus import EXITING_STATUSES, fetch_consensus_validators
from src.validators.oracles import poll_consolidation_signature
from src.validators.register_validators import submit_consolidate_validators
from src.validators.typings import ConsensusValidator

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
    '--wallet-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_PASSWORD_FILE',
    help='Absolute path to the wallet password file. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--wallet-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_FILE',
    help='Absolute path to the wallet. '
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
    help='Performs a vault validators consolidation from 0x01 validators to 0x02 validator. '
    'Switches a validator from 0x01 to 0x02 if the source and target keys are identical.'
)
# pylint: disable-next=too-many-arguments
def consolidate(
    network: str,
    vault: ChecksumAddress,
    execution_endpoints: str,
    consensus_endpoints: str,
    data_dir: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
    verbose: bool,
    no_confirm: bool,
    log_level: str,
    source_public_keys: list[HexStr] | None,
    source_public_keys_file: Path | None,
    target_public_key: HexStr | None = None,
) -> None:
    if all([source_public_keys, source_public_keys_file]):
        raise click.ClickException(
            'Provide only one parameter: either --from-public-keys-file or --from-public-keys.'
        )
    if not any([source_public_keys, source_public_keys_file]) and target_public_key:
        raise click.ClickException(
            'One of these parameters must be provided with target-public-key:'
            ' --from-public-keys-file or --from-public-keys.'
        )

    if source_public_keys_file:
        source_public_keys = _load_public_keys(source_public_keys_file)

    operator_config = OperatorConfig(Path(data_dir))
    operator_config.load(network=network)

    settings.set(
        vaults=[vault],
        network=operator_config.network,
        data_dir=operator_config.data_dir,
        execution_endpoints=execution_endpoints,
        consensus_endpoints=consensus_endpoints,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
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
    source_public_keys: list[HexStr] | None,
    target_public_key: HexStr | None,
    no_confirm: bool,
) -> None:
    # pylint: disable=line-too-long
    """
    Consolidate validators from source public keys to target public key.
    First validate the consolidation request is correct and consensus can handle it.
    Check validation details: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#new-process_consolidation_request
    Then send the request to the contract.
    """
    setup_logging()
    await setup_clients()
    chain_head = await get_chain_finalized_head()

    await _check_validators_manager(vault_address)
    await _check_consolidations_queue()

    if source_public_keys is not None and target_public_key is not None:
        # keys provided by the user
        await _check_public_keys(
            vault_address=vault_address,
            source_public_keys=source_public_keys,
            target_public_key=target_public_key,
            chain_head=chain_head,
        )
        target_source_public_keys = [
            (target_public_key, source_key) for source_key in source_public_keys
        ]

    else:
        target_source_public_keys = await _find_target_source_public_keys(
            vault_address=vault_address,
            chain_head=chain_head,
        )
        if not target_source_public_keys:
            raise click.ClickException(
                f'Validators in vault {vault_address} can\'t be consolidated'
            )

    click.secho(
        f'Consolidating {len(target_source_public_keys)} validator(s): ',
    )
    for target_key, source_key in target_source_public_keys:
        click.secho(f'    {source_key} -> {target_key}')
    if not no_confirm:
        click.confirm(
            'Proceed consolidation?',
            default=True,
            abort=True,
        )

    default_fee = await get_execution_request_fee(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
    )
    if default_fee > MAX_CONSOLIDATION_REQUEST_FEE:
        logger.info(
            'The current consolidation fee per one consolidation (%s Gwei) exceeds the maximum allowed (%s Gwei). '
            'You can override the limit using '
            'the MAX_CONSOLIDATION_REQUEST_FEE environment variable.',
            default_fee,
            MAX_CONSOLIDATION_REQUEST_FEE,
        )
        return
    # Current fee calculated for the number of validators consolidated + gap
    # in case there are some other consolidations in the network.
    current_fee = Gwei(default_fee * len(target_source_public_keys) + default_fee)
    gas_manager = build_gas_manager()
    if not await gas_manager.check_gas_price():
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


async def _check_public_keys(
    vault_address: ChecksumAddress,
    source_public_keys: list[HexStr],
    target_public_key: HexStr,
    chain_head: ChainHead,
) -> None:
    """Validate that provided public keys can be consolidated."""
    logger.info('Checking selected validators for consolidation...')
    all_public_keys = source_public_keys + [target_public_key]
    active_validators = await fetch_consensus_validators(source_public_keys + [target_public_key])
    active_public_keys = {
        val.public_key for val in active_validators if val.status not in EXITING_STATUSES
    }
    non_active_public_keys = set(all_public_keys) - active_public_keys
    for key in non_active_public_keys:
        raise click.ClickException(f'Trying to consolidate non-active validator {key}.')

    source_indexes = set()
    # Verify the source has been active long enough
    max_activation_epoch = chain_head.epoch - settings.network_config.SHARD_COMMITTEE_PERIOD
    for validator in active_validators:
        if validator.public_key in source_public_keys:
            source_indexes.add(validator.index)
            if validator.activation_epoch > max_activation_epoch:
                raise click.ClickException(
                    f'Validator {validator.public_key} is not active enough for consolidation. '
                    f'It must be active for at least '
                    f'{settings.network_config.SHARD_COMMITTEE_PERIOD} epochs before consolidation.'
                )

    #  Verify the source validators has no pending withdrawals in the queue
    await _check_pending_balance_to_withdraw(validator_indexes=source_indexes)

    # validate that target_public_key is a compounding validator.
    # Not required for a single validator consolidation
    if not _is_switch_to_compounding(source_public_keys, target_public_key):
        target_validator = find_first(
            active_validators, lambda val: val.public_key == target_public_key
        )
        # `target_validator` is not None, because of validation above
        target_validator = cast(ConsensusValidator, target_validator)
        if not target_validator.is_compounding:
            raise click.ClickException(
                f'The target validator {target_public_key} is not a compounding validator.'
            )

    logger.info('Fetching vault validators...')
    vault_validators = await VaultContract(vault_address).get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=chain_head.block_number,
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


async def _check_validators_manager(vault_address: ChecksumAddress) -> None:
    vault_contract = VaultContract(vault_address)
    validators_manager = await vault_contract.validators_manager()
    if validators_manager != wallet.account.address:
        raise click.ClickException(
            f'The Validators Manager role must be assigned to the address {wallet.account.address}.'
            f' Please update it in the vault settings.'
        )


async def _check_consolidations_queue() -> None:
    pending_consolidations = await consensus_client.get_pending_consolidations()
    queue_length = len(pending_consolidations)
    if queue_length >= settings.network_config.PENDING_CONSOLIDATIONS_LIMIT:
        raise click.ClickException(
            'Pending consolidations queue has exceeded its limit. Please try again later.'
        )


async def _check_pending_balance_to_withdraw(validator_indexes: set[int]) -> None:
    """Verify the source validators has no pending withdrawals in the queue"""
    pending_partial_withdrawals = await consensus_client.get_pending_partial_withdrawals()
    for withdrawal in pending_partial_withdrawals:
        if int(withdrawal['validator_index']) in validator_indexes and withdrawal['amount']:
            raise click.ClickException(
                f'Validator {withdrawal['validator_index']} '
                f'has pending partial withdrawals in the queue. '
            )


def _encode_validators(target_source_public_keys: list[tuple[HexStr, HexStr]]) -> bytes:
    validators_data = b''
    for target_key, source_key in target_source_public_keys:
        validators_data += Web3.to_bytes(hexstr=source_key)
        validators_data += Web3.to_bytes(hexstr=target_key)
    return validators_data


def _is_switch_to_compounding(source_public_keys: list[HexStr], target_public_key: HexStr) -> bool:
    return len(source_public_keys) == 1 and source_public_keys[0] == target_public_key


def _load_public_keys(public_keys_file: Path) -> list[HexStr]:
    """Loads public keys from file."""
    with open(public_keys_file, 'r', encoding='utf-8') as f:
        public_keys = [HexStr(line.rstrip()) for line in f]

    return public_keys


# pylint: disable-next=too-many-locals
async def _find_target_source_public_keys(
    vault_address: ChecksumAddress, chain_head: ChainHead
) -> list[tuple[HexStr, HexStr]]:
    """
    If there are no 0x02 validators,
    take the oldest 0x01 validator and convert it to 0x02 with confirmation prompt.
    If there is 0x02 validator,
    take the oldest 0x01 validators to top up its balance to 2048 ETH / 64 GNO.
    """
    max_activation_epoch = chain_head.epoch - settings.network_config.SHARD_COMMITTEE_PERIOD

    current_consolidations = await consensus_client.get_pending_consolidations()
    consolidating_indexes = set()
    for cons in current_consolidations:
        consolidating_indexes.add(int(cons['source_index']))
        consolidating_indexes.add(int(cons['target_index']))

    pending_partial_withdrawals = await consensus_client.get_pending_partial_withdrawals()
    pending_partial_withdrawals_indexes = {
        int(withdrawal['validator_index'])
        for withdrawal in pending_partial_withdrawals
        if withdrawal['amount']
    }

    vault_contract = VaultContract(vault_address)
    public_keys = await vault_contract.get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=chain_head.block_number,
    )
    active_validators = [
        val
        for val in await fetch_consensus_validators(public_keys)
        if val.status not in EXITING_STATUSES and val.index not in consolidating_indexes
    ]
    source_validators = []
    for val in active_validators:
        if val.is_compounding:
            continue
        if val.activation_epoch >= max_activation_epoch:
            continue
        if val.index in pending_partial_withdrawals_indexes:
            continue
        source_validators.append(val)

    if not source_validators:
        return []

    source_validators = sorted(source_validators, key=lambda val: val.activation_epoch)

    compounding_validators = [val for val in active_validators if val.is_compounding]
    if compounding_validators:
        # there is at least one 0x02 validator, top up from the one with smallest balance
        target_validator = min(compounding_validators, key=lambda val: val.balance)
        selected_source_validators: list[ConsensusValidator] = []
        for val in source_validators:
            if (
                target_validator.balance + sum(v.balance for v in selected_source_validators)
                > MAX_EFFECTIVE_BALANCE_GWEI
            ):
                break
            selected_source_validators.append(val)

        if selected_source_validators:
            return [
                (target_validator.public_key, val.public_key) for val in selected_source_validators
            ]

    # there are no 0x02 validators, switch the oldest 0x01 to 0x02
    return [(source_validators[0].public_key, source_validators[0].public_key)]
