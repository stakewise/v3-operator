import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress, HexStr
from sw_utils import ChainHead
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import consensus_client, execution_client, setup_clients
from src.common.consensus import get_chain_epoch_head, get_chain_justified_head
from src.common.contracts import VaultContract
from src.common.execution import (
    build_gas_manager,
    get_consolidation_request_fee,
    get_consolidation_requests_count,
    get_protocol_config,
)
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.common.validators import (
    validate_eth_address,
    validate_max_validator_balance_gwei,
    validate_public_key,
    validate_public_keys,
    validate_public_keys_file,
)
from src.common.wallet import wallet
from src.config.config import OperatorConfig
from src.config.networks import GNOSIS, MAINNET, NETWORKS
from src.config.settings import (
    CONSOLIDATIONS_PROCESSING_EPOCHS_INTERVAL,
    DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI,
    settings,
)
from src.validators.consensus import EXITING_STATUSES, fetch_consensus_validators
from src.validators.oracles import poll_consolidation_signature
from src.validators.register_validators import submit_consolidate_validators
from src.validators.relayer import RelayerClient
from src.validators.typings import ConsensusValidator

logger = logging.getLogger(__name__)


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
    help='Comma separated list of public keys of validators to consolidate from.',
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
    prompt='Enter the comma separated list of API endpoints for execution nodes',
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
    '--relayer-endpoint',
    type=str,
    help='Relayer endpoint.',
    envvar='RELAYER_ENDPOINT',
)
@click.option(
    '--max-validator-balance-gwei',
    type=int,
    envvar='MAX_VALIDATOR_BALANCE_GWEI',
    help=f'The maximum validator balance in Gwei.'
    f'Default is {NETWORKS[MAINNET].MAX_VALIDATOR_BALANCE_GWEI} Gwei for Ethereum, '
    f'{NETWORKS[GNOSIS].MAX_VALIDATOR_BALANCE_GWEI} Gwei for Gnosis.',
    callback=validate_max_validator_balance_gwei,
)
@click.option(
    '--max-consolidation-request-fee-gwei',
    type=int,
    envvar='MAX_CONSOLIDATION_REQUEST_FEE_GWEI',
    help='The maximum consolidation request fee in Gwei. '
    f'Default is {DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI} Gwei.',
    default=DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI,
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--no-switch-consolidation',
    is_flag=True,
    default=False,
    help='Disables switching a 0x01 validator to 0x02 when no public keys are provided.',
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
# pylint: disable-next=too-many-arguments,too-many-locals
def consolidate(
    vault: ChecksumAddress,
    execution_endpoints: str,
    consensus_endpoints: str,
    data_dir: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
    verbose: bool,
    no_switch_consolidation: bool,
    no_confirm: bool,
    log_level: str,
    max_consolidation_request_fee_gwei: int,
    source_public_keys: list[HexStr] | None,
    source_public_keys_file: Path | None,
    target_public_key: HexStr | None = None,
    relayer_endpoint: str | None = None,
    max_validator_balance_gwei: int | None = None,
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

    operator_config = OperatorConfig(vault, Path(data_dir))
    operator_config.load()

    settings.set(
        vault=vault,
        network=operator_config.network,
        vault_dir=operator_config.vault_dir,
        execution_endpoints=execution_endpoints,
        consensus_endpoints=consensus_endpoints,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        relayer_endpoint=relayer_endpoint,
        max_validator_balance_gwei=(
            Gwei(max_validator_balance_gwei) if max_validator_balance_gwei else None
        ),
        verbose=verbose,
        log_level=log_level,
    )
    try:
        asyncio.run(
            main(
                vault_address=vault,
                source_public_keys=source_public_keys,
                target_public_key=target_public_key,
                no_switch_consolidation=no_switch_consolidation,
                max_consolidation_request_fee_gwei=Gwei(max_consolidation_request_fee_gwei),
                no_confirm=no_confirm,
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


# pylint: disable-next=too-many-locals,too-many-arguments
async def main(
    vault_address: ChecksumAddress,
    source_public_keys: list[HexStr] | None,
    target_public_key: HexStr | None,
    no_switch_consolidation: bool,
    max_consolidation_request_fee_gwei: Gwei,
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
    chain_head = await get_chain_justified_head()

    await _check_validators_manager(vault_address)
    await _check_consolidations_queue()
    last_submitted_consolidations = await _fetch_last_contract_submitted_consolidations(
        vault_address, chain_head
    )
    if source_public_keys is not None and target_public_key is not None:
        # keys provided by the user
        target_source = await _check_public_keys(
            vault_address=vault_address,
            source_public_keys=source_public_keys,
            target_public_key=target_public_key,
            last_submitted_consolidations=last_submitted_consolidations,
            chain_head=chain_head,
        )

    else:
        target_source = await _find_target_source_public_keys(
            vault_address=vault_address,
            last_submitted_consolidations=last_submitted_consolidations,
            chain_head=chain_head,
        )
        if not target_source:
            raise click.ClickException(
                f'Validators in vault {vault_address} can\'t be consolidated'
            )

    for target_validator, source_validator in target_source:
        if source_validator.index == target_validator.index:
            if no_switch_consolidation:
                raise click.ClickException(
                    f'Validator with index {source_validator.index} can\'t be consolidated as switching is disabled.'
                )
            click.secho(
                f'Switching validator with index {source_validator.index} to compounding',
            )
        else:
            click.secho(
                f'Consolidating from validator with index {source_validator.index} '
                f'to validator with index {target_validator.index}'
            )
    if not no_confirm:
        click.confirm(
            'Proceed consolidation?',
            default=True,
            abort=True,
        )

    gas_manager = build_gas_manager()
    if not await gas_manager.check_gas_price():
        return

    protocol_config = await get_protocol_config()

    target_source_public_keys = [
        (target_validator.public_key, source_validator.public_key)
        for target_validator, source_validator in target_source
    ]
    consolidations_count = len(target_source_public_keys)

    consolidation_request_fee = await get_consolidation_request_fee(count=consolidations_count)
    if consolidation_request_fee > Web3.to_wei(max_consolidation_request_fee_gwei, 'gwei'):
        logger.info(
            'The current consolidation fee per one consolidation (%s Gwei) exceeds the maximum allowed (%s Gwei). '
            'You can override the limit using the MAX_CONSOLIDATION_REQUEST_FEE_GWEI environment variable.',
            Web3.from_wei(consolidation_request_fee, 'gwei'),
            max_consolidation_request_fee_gwei,
        )
        return

    oracle_signatures = None
    if (
        len(target_source_public_keys) == 1
        and target_source_public_keys[0][0] == target_source_public_keys[0][1]
    ):
        # The oracles signatures are only required when switching from 0x01 to 0x02
        oracle_signatures = await poll_consolidation_signature(
            target_public_keys=[target_source_public_keys[0][0]],
            vault=vault_address,
            protocol_config=protocol_config,
        )

    encoded_validators = _encode_validators(target_source_public_keys)
    validators_manager_signature = await _get_validators_manager_signature(
        vault_address, target_source_public_keys
    )

    tx_hash = await submit_consolidate_validators(
        validators=encoded_validators,
        oracle_signatures=oracle_signatures,
        tx_fee=Wei(consolidation_request_fee * consolidations_count),
        validators_manager_signature=validators_manager_signature,
    )

    if tx_hash:
        click.secho(
            'Validators have been successfully consolidated',
            bold=True,
            fg='green',
        )


# pylint: disable-next=too-many-branches
async def _check_public_keys(
    vault_address: ChecksumAddress,
    source_public_keys: list[HexStr],
    target_public_key: HexStr,
    last_submitted_consolidations: set[HexStr],
    chain_head: ChainHead,
) -> list[tuple[ConsensusValidator, ConsensusValidator]]:
    """
    Validate that provided public keys can be consolidated
    and returns the target and source validators info.
    """
    logger.info('Checking selected validators for consolidation...')

    # Validate that source public keys are unique
    if len(source_public_keys) != len(set(source_public_keys)):
        raise click.ClickException('Source public keys must be unique.')

    # Validate the switch from 0x01 to 0x02 and consolidation to another validator
    if len(source_public_keys) > 1 and target_public_key in source_public_keys:
        raise click.ClickException(
            'Cannot switch from 0x01 to 0x02 and consolidate '
            'to another validator in the same request.'
        )
    if target_public_key in last_submitted_consolidations:
        raise click.ClickException(
            f'Target validator {target_public_key} has submitted consolidation '
            f'in the last {CONSOLIDATIONS_PROCESSING_EPOCHS_INTERVAL} epochs.'
        )
    for source_public_key in source_public_keys:
        if source_public_key in last_submitted_consolidations:
            raise click.ClickException(
                f'Source validator {source_public_key} has submitted consolidation '
                f'in the last {CONSOLIDATIONS_PROCESSING_EPOCHS_INTERVAL} epochs.'
            )
    # Fetch source and target validators
    validators = await fetch_consensus_validators(source_public_keys + [target_public_key])
    pubkey_to_validator = {val.public_key: val for val in validators}

    source_validators: list[ConsensusValidator] = []
    max_activation_epoch = chain_head.epoch - settings.network_config.SHARD_COMMITTEE_PERIOD

    # Validate source public keys
    for source_public_key in source_public_keys:
        source_validator = pubkey_to_validator.get(source_public_key)

        if not source_validator:
            raise click.ClickException(
                f'Validator {source_public_key} not found in the consensus layer.'
            )

        # Validate the source validator status
        if source_validator.status in EXITING_STATUSES:
            raise click.ClickException(
                f'Validator {source_public_key} is in exiting '
                f'status {source_validator.status.value}.'
            )

        # Validate the source has been active long enough
        if source_validator.activation_epoch > max_activation_epoch:
            raise click.ClickException(
                f'Validator {source_validator.public_key} is not active enough for consolidation. '
                f'It must be active for at least '
                f'{settings.network_config.SHARD_COMMITTEE_PERIOD} epochs before consolidation.'
            )
        source_validators.append(source_validator)

    # Validate target public key
    target_validator = pubkey_to_validator.get(target_public_key)
    if not target_validator:
        raise click.ClickException(
            f'Target validator {target_public_key} not found in the consensus layer.'
        )
    if target_validator.status in EXITING_STATUSES:
        raise click.ClickException(
            f'Target validator {target_public_key} is in exiting '
            f'status {target_validator.status.value}.'
        )

    # Validate that target validator is a compounding validator.
    # Not required for a switch from 0x01 to 0x02.
    if not _is_switch_to_compounding(source_public_keys, target_public_key):
        if not target_validator.is_compounding:
            raise click.ClickException(
                f'The target validator {target_public_key} is not a compounding validator.'
            )

    # Validate the source validators has no pending withdrawals in the queue
    await _check_pending_balance_to_withdraw(
        validator_indexes={val.index for val in source_validators}
    )

    # Validate the source and target validators are in the vault
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

    # Validate the total balance won't exceed the max effective balance
    if sum(val.balance for val in validators) > settings.max_validator_balance_gwei:
        raise click.ClickException(
            'Cannot consolidate validators,'
            f' total balance exceed {settings.max_validator_balance_gwei} Gwei'
        )

    return [(target_validator, source_validator) for source_validator in source_validators]


async def _check_validators_manager(vault_address: ChecksumAddress) -> None:
    if settings.relayer_endpoint:
        return
    vault_contract = VaultContract(vault_address)
    validators_manager = await vault_contract.validators_manager()
    if validators_manager != wallet.account.address:
        raise click.ClickException(
            f'The Validators Manager role must be assigned to the address {wallet.account.address}.'
            f' Please update it in the vault settings.'
        )


async def _check_consolidations_queue() -> None:
    pending_consolidations_consensus = await consensus_client.get_pending_consolidations()
    pending_consolidations_execution_count = await get_consolidation_requests_count()
    queue_length = len(pending_consolidations_consensus) + pending_consolidations_execution_count
    if queue_length >= settings.network_config.PENDING_CONSOLIDATIONS_LIMIT:
        raise click.ClickException(
            'Pending consolidations queue has exceeded its limit. Please try again later.'
        )


async def _fetch_last_contract_submitted_consolidations(
    vault_address: ChecksumAddress, chain_head: ChainHead
) -> set[HexStr]:
    vault_contract = VaultContract(vault_address)

    previous_epoch = max(chain_head.epoch - CONSOLIDATIONS_PROCESSING_EPOCHS_INTERVAL, 0)
    previous_chain_head = await get_chain_epoch_head(previous_epoch)
    last_events = await vault_contract.get_consolidation_events(
        from_block=previous_chain_head.block_number,
        to_block=await execution_client.eth.get_block_number(),
    )
    public_keys = set()
    for event in last_events:
        public_keys.add(Web3.to_hex(event['args']['fromPublicKey']))
        public_keys.add(Web3.to_hex(event['args']['toPublicKey']))
    return public_keys


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


async def _find_target_source_public_keys(
    vault_address: ChecksumAddress,
    chain_head: ChainHead,
    last_submitted_consolidations: set[HexStr],
) -> list[tuple[ConsensusValidator, ConsensusValidator]]:
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

    logger.info('Fetching vault validators...')
    vault_contract = VaultContract(vault_address)
    public_keys = await vault_contract.get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=chain_head.block_number,
    )
    active_validators = [
        val
        for val in await fetch_consensus_validators(public_keys)
        if val.status not in EXITING_STATUSES
        and val.index not in consolidating_indexes
        and val.public_key not in last_submitted_consolidations
    ]

    source_validators = await _get_source_validators(
        active_validators=active_validators,
        max_activation_epoch=max_activation_epoch,
    )
    if not source_validators:
        return []

    source_validators.sort(key=lambda val: val.activation_epoch)

    compounding_validators = [val for val in active_validators if val.is_compounding]
    if compounding_validators:
        # there is at least one 0x02 validator, top up from the one with smallest balance
        target_validator = min(compounding_validators, key=lambda val: val.balance)
        selected_source_validators: list[ConsensusValidator] = []
        for val in source_validators:
            if (
                target_validator.balance + sum(v.balance for v in selected_source_validators)
                > settings.max_validator_balance_gwei
            ):
                break
            selected_source_validators.append(val)

        if selected_source_validators:
            return [(target_validator, val) for val in selected_source_validators]

    # there are no 0x02 validators, switch the oldest 0x01 to 0x02
    return [(source_validators[0], source_validators[0])]


async def _get_source_validators(
    active_validators: list[ConsensusValidator], max_activation_epoch: int
) -> list[ConsensusValidator]:
    pending_partial_withdrawals = await consensus_client.get_pending_partial_withdrawals()
    pending_partial_withdrawals_indexes = {
        int(withdrawal['validator_index'])
        for withdrawal in pending_partial_withdrawals
        if withdrawal['amount']
    }

    source_validators = []
    for val in active_validators:
        if val.is_compounding:
            continue
        if val.activation_epoch >= max_activation_epoch:
            continue
        if val.index in pending_partial_withdrawals_indexes:
            continue
        source_validators.append(val)

    return source_validators


async def _get_validators_manager_signature(
    vault_address: ChecksumAddress, target_source_public_keys: list[tuple[HexStr, HexStr]]
) -> HexStr:
    if not settings.relayer_endpoint:
        return HexStr('0x')
    relayer = RelayerClient()
    # fetch validator manager signature from relayer
    relayer_response = await relayer.consolidate_validators(
        vault_address=vault_address,
        target_source_public_keys=target_source_public_keys,
    )
    if not relayer_response.validators_manager_signature:
        raise click.ClickException('Could not get validator manager signature from relayer')

    return relayer_response.validators_manager_signature
