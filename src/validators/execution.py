import logging
import struct
from typing import Set

from eth_typing import BlockNumber, HexStr
from multiproof import StandardMerkleTree
from sw_utils import (
    EventProcessor,
    get_eth1_withdrawal_credentials,
    is_valid_deposit_data_signature,
)
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import EventData, Wei

from src.common.clients import execution_client
from src.common.contracts import (
    keeper_contract,
    validators_registry_contract,
    vault_contract,
)
from src.common.ipfs import fetch_harvest_params
from src.common.metrics import metrics
from src.config.networks import ETH_NETWORKS
from src.config.settings import DEPOSIT_AMOUNT, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.signing import encode_tx_validator, get_single_validator_proof
from src.validators.typings import (
    DepositData,
    Keystores,
    NetworkValidator,
    OraclesApproval,
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
    async def process_events(events: list[EventData]) -> None:
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


async def get_withdrawable_assets() -> tuple[Wei, HexStr | None]:
    """Fetches vault's available assets for staking."""
    before_update_assets = await vault_contract.functions.withdrawableAssets().call()

    last_rewards = await keeper_contract.get_last_rewards_update()
    if last_rewards is None:
        return before_update_assets, None

    harvest_params = await fetch_harvest_params(
        vault_address=settings.vault,
        ipfs_hash=last_rewards.ipfs_hash,
        rewards_root=last_rewards.rewards_root,
    )
    if harvest_params is None:
        return before_update_assets, None

    update_state_call = vault_contract.encodeABI(
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
    withdrawable_assets_call = vault_contract.encodeABI(fn_name='withdrawableAssets', args=[])

    multicall = await vault_contract.functions.multicall(
        [update_state_call, withdrawable_assets_call]
    ).call()
    after_update_assets = Web3.to_int(multicall[1])

    before_update_validators = before_update_assets // DEPOSIT_AMOUNT
    after_update_validators = after_update_assets // DEPOSIT_AMOUNT
    if before_update_validators != after_update_validators or await keeper_contract.can_harvest(
        vault_contract.contract_address
    ):
        return Wei(after_update_assets), update_state_call

    return Wei(before_update_assets), None


async def check_deposit_data_root(deposit_data_root: str) -> None:
    """Checks whether deposit data root matches validators root in Vault."""
    if deposit_data_root != Web3.to_hex(await vault_contract.get_validators_root()):
        raise RuntimeError(
            "Deposit data tree root and vault's validators root don't match."
            ' Have you updated vault deposit data?'
        )


async def get_available_validators(
    keystores: Keystores, deposit_data: DepositData, count: int
) -> list[Validator]:
    """Fetches vault's available validators."""
    await check_deposit_data_root(deposit_data.tree.root)

    start_index = await vault_contract.get_validators_index()
    validators: list[Validator] = []
    if len(deposit_data.validators) < count:
        return []

    for i in range(start_index, start_index + count):
        validator = deposit_data.validators[i]
        if validator.public_key not in keystores:
            logger.warning(
                'Cannot find validator with public key %s in imported keystores.',
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


async def update_unused_validator_keys_metric(
    keystores: Keystores, deposit_data: DepositData
) -> int:
    try:
        await check_deposit_data_root(deposit_data.tree.root)
    except RuntimeError:
        metrics.unused_validator_keys.set(0)
        return 0

    validators: int = 0
    for validator in deposit_data.validators:
        if validator.public_key not in keystores:
            continue
        if NetworkValidatorCrud().is_validator_registered(validator.public_key):
            continue
        validators += 1

    metrics.unused_validator_keys.set(validators)

    return validators


async def register_single_validator(
    tree: StandardMerkleTree,
    validator: Validator,
    approval: OraclesApproval,
    update_state_call: HexStr | None,
    validators_registry_root: Bytes32,
) -> None:
    """Registers single validator."""
    if settings.network not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    tx_validator, proof = get_single_validator_proof(tree=tree, validator=validator)

    logger.info('Submitting registration transaction')
    register_call_args = [
        (
            validators_registry_root,
            tx_validator,
            approval.signatures,
            approval.ipfs_hash,
        ),
        proof,
    ]
    if update_state_call is not None:
        register_call = vault_contract.encodeABI(
            fn_name='registerValidator',
            args=register_call_args,
        )
        tx = await vault_contract.functions.multicall([update_state_call, register_call]).transact()
    else:
        tx = await vault_contract.functions.registerValidator(*register_call_args).transact()

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)


# pylint: disable-next=too-many-locals
async def register_multiple_validator(
    tree: StandardMerkleTree,
    validators: list[Validator],
    approval: OraclesApproval,
    update_state_call: HexStr | None,
    validators_registry_root: Bytes32,
) -> None:
    """Registers multiple validators."""
    if settings.network not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    credentials = get_eth1_withdrawal_credentials(settings.vault)
    tx_validators: list[bytes] = []
    leaves: list[tuple[bytes, int]] = []
    for validator in validators:
        tx_validator = encode_tx_validator(credentials, validator)
        tx_validators.append(tx_validator)
        leaves.append((tx_validator, validator.deposit_data_index))

    multi_proof = tree.get_multi_proof(leaves)
    sorted_tx_validators: list[bytes] = [v[0] for v in multi_proof.leaves]
    indexes = [sorted_tx_validators.index(v) for v in tx_validators]

    logger.info('Submitting registration transaction')
    register_call_args = [
        (
            validators_registry_root,
            b''.join(tx_validators),
            approval.signatures,
            approval.ipfs_hash,
        ),
        indexes,
        multi_proof.proof_flags,
        multi_proof.proof,
    ]
    if update_state_call is not None:
        register_call = vault_contract.encodeABI(
            fn_name='registerValidators',
            args=register_call_args,
        )
        tx = await vault_contract.functions.multicall([update_state_call, register_call]).transact()
    else:
        tx = await vault_contract.functions.registerValidators(*register_call_args).transact()

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)
