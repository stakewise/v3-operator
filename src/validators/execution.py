import logging
import struct
from typing import Set

from Cryptodome.PublicKey import RSA
from eth_typing import BlockNumber, HexStr
from multiproof import StandardMerkleTree
from sw_utils import (
    EventProcessor,
    compute_deposit_data,
    get_eth1_withdrawal_credentials,
    is_valid_deposit_data_signature,
)
from sw_utils.decorators import backoff_aiohttp_errors
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import EventData, Wei

from src.common.accounts import operator_account
from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import (
    oracles_contract,
    validators_registry_contract,
    vault_contract,
)
from src.config.networks import ETH_NETWORKS
from src.config.settings import (
    DEFAULT_RETRY_TIME,
    DEPOSIT_AMOUNT_GWEI,
    NETWORK,
    NETWORK_CONFIG,
    VAULT_CONTRACT_ADDRESS,
)
from src.validators.database import (
    get_last_network_validator,
    is_validator_registered,
    save_network_validators,
)
from src.validators.typings import (
    DepositData,
    KeeperApprovalParams,
    Keystores,
    MultipleValidatorRegistration,
    NetworkValidator,
    Oracles,
    OraclesApproval,
    SingleValidatorRegistration,
    Validator,
)

VALIDATORS_REGISTRY_GENESIS_BLOCK: BlockNumber = NETWORK_CONFIG.VALIDATORS_REGISTRY_GENESIS_BLOCK
GENESIS_FORK_VERSION: bytes = NETWORK_CONFIG.GENESIS_FORK_VERSION

logger = logging.getLogger(__name__)


class NetworkValidatorsProcessor(EventProcessor):
    contract = validators_registry_contract
    contract_event = 'DepositEvent'

    @staticmethod
    async def get_from_block() -> BlockNumber:
        last_validator = get_last_network_validator()
        if not last_validator:
            return VALIDATORS_REGISTRY_GENESIS_BLOCK

        return BlockNumber(last_validator.block_number + 1)

    @staticmethod
    async def process_events(events: list[EventData]) -> None:
        validators = process_network_validator_events(events)
        save_network_validators(validators)


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
    if is_valid_deposit_data_signature(
        public_key, withdrawal_creds, signature, amount_gwei, GENESIS_FORK_VERSION
    ):
        return Web3.to_hex(public_key)

    return None


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def get_latest_network_validator_public_keys() -> Set[HexStr]:
    """Fetches the latest network validator public keys."""
    last_validator = get_last_network_validator()
    if last_validator:
        from_block = BlockNumber(last_validator.block_number + 1)
    else:
        from_block = VALIDATORS_REGISTRY_GENESIS_BLOCK

    new_events = await validators_registry_contract.events.DepositEvent.get_logs(
        from_block=from_block
    )
    new_public_keys: Set[HexStr] = set()
    for event in new_events:
        public_key = process_network_validator_event(event)
        if public_key:
            new_public_keys.add(public_key)

    return new_public_keys


@backoff_aiohttp_errors(max_time=300)
async def get_operator_balance() -> Wei:
    return await execution_client.eth.get_balance(operator_account.address)  # type: ignore


async def check_operator_balance() -> None:
    operator_min_balance = NETWORK_CONFIG.OPERATOR_MIN_BALANCE
    symbol = NETWORK_CONFIG.SYMBOL

    if operator_min_balance <= 0:
        return

    if (await get_operator_balance()) < operator_min_balance:
        logger.warning(
            'Operator balance is too low. At least %s %s is recommended.',
            Web3.from_wei(operator_min_balance, 'ether'),
            symbol,
        )


@backoff_aiohttp_errors(max_time=300)
async def get_withdrawable_assets() -> Wei:
    """Fetches vault's available assets for staking."""
    return await vault_contract.functions.withdrawableAssets().call()


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def get_validators_registry_root() -> Bytes32:
    """Fetches the latest validators registry root."""
    return await validators_registry_contract.functions.get_deposit_root().call()


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def get_vault_validators_root() -> Bytes32:
    """Fetches vault's validators root."""
    return await vault_contract.functions.validatorsRoot().call()


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def get_vault_validators_index() -> int:
    """Fetches vault's current validators index."""
    return await vault_contract.functions.validatorIndex().call()


async def check_deposit_data_root(deposit_data_root: str) -> None:
    """Checks whether deposit data root matches validators root in Vault."""
    if deposit_data_root != Web3.to_hex(await get_vault_validators_root()):
        raise RuntimeError(
            "Deposit data tree root and vault's validators root don't match."
            ' Have you updated vault deposit data?'
        )


async def get_available_validators(
    keystores: Keystores, deposit_data: DepositData, count: int
) -> list[Validator]:
    """Fetches vault's available validators."""
    await check_deposit_data_root(deposit_data.tree.root)

    start_index = await get_vault_validators_index()
    validators: list[Validator] = []
    for i in range(start_index, start_index + count):
        validator = deposit_data.validators[i]
        if validator.public_key not in keystores:
            logger.warning(
                'Cannot find validator with public key %s in imported keystores.',
                validator.public_key,
            )
            break

        if is_validator_registered(validator.public_key):
            logger.warning(
                'Validator with public key %s is already registered.'
                ' You must upload new deposit data.',
                validator.public_key,
            )
            break

        validators.append(validator)

    return validators


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def get_oracles() -> Oracles:
    """Fetches oracles config."""
    events = await oracles_contract.events.ConfigUpdated.get_logs(
        from_block=NETWORK_CONFIG.ORACLES_GENESIS_BLOCK
    )
    if not events:
        raise ValueError('Failed to fetch IPFS hash of oracles config')

    # fetch IPFS record
    ipfs_hash = events[-1]['args']['configIpfsHash']
    config = await ipfs_fetch_client.fetch_json(ipfs_hash)
    threshold = await oracles_contract.functions.requiredOracles().call()

    rsa_public_keys = []
    endpoints = []
    addresses = []
    for oracle in config:
        addresses.append(Web3.to_checksum_address(oracle['address']))
        rsa_public_keys.append(RSA.import_key(oracle['rsa_public_key']))
        endpoints.append(oracle['endpoint'])

    if not 1 <= threshold <= len(rsa_public_keys):
        raise ValueError('Invalid threshold in oracles config')

    return Oracles(
        threshold=threshold,
        rsa_public_keys=rsa_public_keys,
        endpoints=endpoints,
        addresses=addresses,
    )


async def register_single_validator(
    tree: StandardMerkleTree, validator: Validator, approval: OraclesApproval
) -> None:
    """Registers single validator."""
    if NETWORK not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    credentials = get_eth1_withdrawal_credentials(VAULT_CONTRACT_ADDRESS)
    tx_validator = _encode_tx_validator(credentials, validator)
    proof = tree.get_proof([tx_validator, validator.deposit_data_index])  # type: ignore

    tx_data = SingleValidatorRegistration(
        keeperParams=KeeperApprovalParams(
            validatorsRegistryRoot=approval.validators_registry_root,
            validators=tx_validator,
            signatures=approval.signatures,
            exitSignaturesIpfsHash=approval.ipfs_hash,
        ),
        proof=proof,
    )
    logger.info('Submitting registration transaction')
    tx = await vault_contract.functions.registerValidator(
        (
            tx_data.keeperParams.validatorsRegistryRoot,
            tx_data.keeperParams.validators,
            tx_data.keeperParams.signatures,
            tx_data.keeperParams.exitSignaturesIpfsHash,
        ),
        tx_data.proof,
    ).transact()  # type: ignore
    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)  # type: ignore


async def register_multiple_validator(
    tree: StandardMerkleTree,
    validators: list[Validator],
    approval: OraclesApproval,
) -> None:
    """Registers multiple validators."""
    if NETWORK not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    credentials = get_eth1_withdrawal_credentials(VAULT_CONTRACT_ADDRESS)
    tx_validators: list[bytes] = []
    leaves: list[tuple[bytes, int]] = []
    for validator in validators:
        tx_validator = _encode_tx_validator(credentials, validator)
        tx_validators.append(tx_validator)
        leaves.append((tx_validator, validator.deposit_data_index))

    multi_proof = tree.get_multi_proof(leaves)
    sorted_tx_validators: list[bytes] = [v[0] for v in multi_proof.leaves]
    indexes = [sorted_tx_validators.index(v) for v in tx_validators]
    tx_data = MultipleValidatorRegistration(
        keeperParams=KeeperApprovalParams(
            validatorsRegistryRoot=approval.validators_registry_root,
            validators=b''.join(tx_validators),
            signatures=approval.signatures,
            exitSignaturesIpfsHash=approval.ipfs_hash,
        ),
        indexes=indexes,
        proofFlags=multi_proof.proof_flags,
        proof=multi_proof.proof,
    )
    logger.info('Submitting registration transaction')
    tx = await vault_contract.functions.registerValidators(
        (
            tx_data.keeperParams.validatorsRegistryRoot,
            tx_data.keeperParams.validators,
            tx_data.keeperParams.signatures,
            tx_data.keeperParams.exitSignaturesIpfsHash,
        ),
        indexes,
        multi_proof.proof_flags,
        multi_proof.proof,
    ).transact()  # type: ignore
    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)  # type: ignore


def _encode_tx_validator(withdrawal_credentials: bytes, validator: Validator) -> bytes:
    public_key = Web3.to_bytes(hexstr=validator.public_key)
    signature = Web3.to_bytes(hexstr=validator.signature)
    deposit_root = compute_deposit_data(
        public_key=public_key,
        withdrawal_credentials=withdrawal_credentials,
        amount_gwei=DEPOSIT_AMOUNT_GWEI,
        signature=signature,
    ).hash_tree_root
    return public_key + signature + deposit_root
