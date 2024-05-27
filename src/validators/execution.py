import logging
import struct
from typing import Sequence, Set

from eth_typing import BlockNumber, HexStr
from multiproof.standard import MultiProof
from sw_utils import EventProcessor, is_valid_deposit_data_signature
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import EventData, Wei

from src.common.clients import execution_client
from src.common.contracts import validators_registry_contract, vault_contract
from src.common.execution import get_high_priority_tx_params
from src.common.metrics import metrics
from src.common.typings import HarvestParams, OraclesApproval
from src.common.utils import format_error
from src.common.vault import Vault
from src.config.settings import DEPOSIT_AMOUNT, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.keystores.base import BaseKeystore
from src.validators.relayer import Relayer
from src.validators.typings import (
    DepositData,
    DepositDataValidator,
    NetworkValidator,
    Validator,
)

logger = logging.getLogger(__name__)


class NetworkValidatorsProcessor(EventProcessor):
    contract_event = 'DepositEvent'

    @property
    def contract(self):
        return validators_registry_contract

    @staticmethod
    async def get_from_block() -> BlockNumber:
        last_validator = NetworkValidatorCrud().get_last_network_validator()
        if not last_validator:
            return settings.network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK

        return BlockNumber(last_validator.block_number + 1)

    @staticmethod
    # pylint: disable-next=unused-argument
    async def process_events(events: list[EventData], to_block: BlockNumber) -> None:
        validators = process_network_validator_events(events)
        NetworkValidatorCrud().save_network_validators(validators)


def process_network_validator_events(events: list[EventData]) -> list[NetworkValidator]:
    """
    Processes `ValidatorsRegistry` registration events
    and returns the list of valid validators.
    """
    result: list[NetworkValidator] = []
    for event in events:
        public_key = process_network_validator_event(event)
        if not public_key:
            continue

        result.append(
            NetworkValidator(public_key=public_key, block_number=BlockNumber(event['blockNumber']))
        )

    return result


def process_network_validator_event(event: EventData) -> HexStr | None:
    """
    Processes validator deposit event
    and returns its public key if the deposit is valid.
    """
    public_key = event['args']['pubkey']
    withdrawal_creds = event['args']['withdrawal_credentials']
    amount_gwei = struct.unpack('<Q', event['args']['amount'])[0]
    signature = event['args']['signature']
    fork_version = settings.network_config.GENESIS_FORK_VERSION
    if is_valid_deposit_data_signature(
        public_key, withdrawal_creds, signature, amount_gwei, fork_version
    ):
        return Web3.to_hex(public_key)

    return None


async def get_latest_network_validator_public_keys() -> Set[HexStr]:
    """Fetches the latest network validator public keys."""
    last_validator = NetworkValidatorCrud().get_last_network_validator()
    if last_validator:
        from_block = BlockNumber(last_validator.block_number + 1)
    else:
        from_block = settings.network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK

    new_events = await validators_registry_contract.events.DepositEvent.get_logs(
        fromBlock=from_block
    )
    new_public_keys: Set[HexStr] = set()
    for event in new_events:
        public_key = process_network_validator_event(event)
        if public_key:
            new_public_keys.add(public_key)

    return new_public_keys


async def get_withdrawable_assets(harvest_params: HarvestParams | None) -> Wei:
    """Fetches vault's available assets for staking."""
    before_update_assets = await vault_contract.functions.withdrawableAssets().call()

    if harvest_params is None:
        return before_update_assets

    update_state_call = vault_contract.encode_abi(
        fn_name='updateState',
        args=[
            (
                harvest_params.rewards_root,
                harvest_params.reward,
                harvest_params.unlocked_mev_reward,
                harvest_params.proof,
            )
        ],
    )
    withdrawable_assets_call = vault_contract.encode_abi(fn_name='withdrawableAssets', args=[])

    multicall = await vault_contract.functions.multicall(
        [update_state_call, withdrawable_assets_call]
    ).call()
    after_update_assets = Web3.to_int(multicall[1])

    before_update_validators = before_update_assets // DEPOSIT_AMOUNT
    after_update_validators = after_update_assets // DEPOSIT_AMOUNT
    if before_update_validators != after_update_validators:
        return Wei(after_update_assets)

    return Wei(before_update_assets)


async def check_deposit_data_root(deposit_data_root: str) -> None:
    """Checks whether deposit data root matches validators root in Vault."""

    vault_deposit_data_root = await Vault().get_validators_root()
    if deposit_data_root != Web3.to_hex(vault_deposit_data_root):
        raise RuntimeError(
            "Deposit data tree root and vault's validators root don't match."
            ' Have you updated vault deposit data?'
        )


async def get_validators_from_deposit_data(
    keystore: BaseKeystore | None,
    deposit_data: DepositData,
    count: int,
    run_check_deposit_data_root: bool = True,
) -> Sequence[DepositDataValidator]:
    """Fetches vault's available validators."""
    if run_check_deposit_data_root:
        await check_deposit_data_root(deposit_data.tree.root)

    start_index = await Vault().get_validators_index()
    validators: list[DepositDataValidator] = []

    for validator in deposit_data.validators[start_index : start_index + count]:
        if keystore and validator.public_key not in keystore:
            logger.warning(
                'Cannot find validator with public key %s in keystores.',
                validator.public_key,
            )
            break

        if NetworkValidatorCrud().is_validator_registered(validator.public_key):
            logger.warning(
                'Validator with public key %s is already registered.'
                ' You must upload new deposit data.',
                validator.public_key,
            )
            break

        validators.append(validator)

    return validators


async def get_validators_from_relayer(
    relayer: Relayer, start_validator_index: int, count: int
) -> Sequence[Validator]:
    validators: list[Validator] = []
    relayer_validators = await relayer.get_validators(start_validator_index, count)

    for validator in relayer_validators[:count]:
        if NetworkValidatorCrud().is_validator_registered(validator.public_key):
            logger.warning(
                'Validator with public key %s is already registered.',
                validator.public_key,
            )
            break

        validators.append(validator)

    return validators


async def update_unused_validator_keys_metric(
    keystore: BaseKeystore,
    deposit_data: DepositData,
) -> int:
    try:
        await check_deposit_data_root(deposit_data.tree.root)
    except RuntimeError:
        metrics.unused_validator_keys.set(0)
        return 0

    validators: int = 0
    for validator in deposit_data.validators:
        if validator.public_key not in keystore:
            continue

        if NetworkValidatorCrud().is_validator_registered(validator.public_key):
            continue
        validators += 1

    metrics.unused_validator_keys.set(validators)

    return validators


async def register_single_validator(
    approval: OraclesApproval,
    multi_proof: MultiProof | None,
    tx_validators: list[bytes],
    harvest_params: HarvestParams | None,
    validators_registry_root: Bytes32,
) -> HexStr | None:
    """Registers single validator."""
    logger.info('Submitting registration transaction')

    keeper_approval_params = (
        validators_registry_root,
        approval.deadline,
        tx_validators[0],
        approval.signatures,
        approval.ipfs_hash,
    )
    register_via_vault_v2: bool = False

    register_call_args: list = [keeper_approval_params]
    if multi_proof:
        register_call_args.append(multi_proof.proof)
    else:
        register_via_vault_v2 = True

    try:
        tx_params = await get_high_priority_tx_params()

        tx = await Vault().register_single_validator(
            tx_params=tx_params,
            harvest_params=harvest_params,
            register_call_args=register_call_args,
            register_via_vault_v2=register_via_vault_v2,
        )
    except Exception as e:
        logger.error('Failed to register validator: %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Registration transaction failed')
        return None

    return tx_hash


async def register_multiple_validator(
    multi_proof: MultiProof | None,
    tx_validators: list[bytes],
    approval: OraclesApproval,
    harvest_params: HarvestParams | None,
    validators_registry_root: Bytes32,
) -> HexStr | None:
    """Registers multiple validators."""
    logger.info('Submitting registration transaction')
    keeper_approval_params = (
        validators_registry_root,
        approval.deadline,
        b''.join(tx_validators),
        approval.signatures,
        approval.ipfs_hash,
    )
    # Vault args
    register_call_args: list = [keeper_approval_params]
    register_via_vault_v2 = False

    if multi_proof:
        sorted_tx_validators: list[bytes] = [v[0] for v in multi_proof.leaves]
        indexes = [sorted_tx_validators.index(v) for v in tx_validators]

        # DepositDataRegistry args
        register_call_args = [
            settings.vault,
            keeper_approval_params,
            indexes,
            multi_proof.proof_flags,
            multi_proof.proof,
        ]
    else:
        register_via_vault_v2 = True

    try:
        tx_params = await get_high_priority_tx_params()
        tx = await Vault().register_multiple_validators(
            tx_params=tx_params,
            harvest_params=harvest_params,
            register_call_args=register_call_args,
            register_via_vault_v2=register_via_vault_v2,
        )
    except Exception as e:
        logger.error('Failed to register validators: %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Registration transaction failed')
        return None
    return tx_hash
