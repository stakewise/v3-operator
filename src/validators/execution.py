import dataclasses
import logging
import struct
from typing import Set

import backoff
from Cryptodome.PublicKey import RSA
from eth_typing import BlockNumber, HexStr
from multiproof import StandardMerkleTree
from sw_utils import (
    EventProcessor,
    compute_deposit_message,
    get_eth1_withdrawal_credentials,
    is_valid_deposit_data_signature,
)
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import EventData, Wei

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import (
    oracles_contract,
    validators_registry_contract,
    vault_contract,
)
from src.config.networks import ETH_NETWORKS
from src.config.settings import (
    DEPOSIT_AMOUNT_GWEI,
    NETWORK,
    NETWORK_CONFIG,
    VAULT_CONTRACT_ADDRESS,
)
from src.validators.database import (
    get_deposit_data,
    get_last_network_validator,
    get_last_validators_root,
    is_validator_registered,
    save_deposit_data,
    save_network_validators,
    save_validators_root,
)
from src.validators.ipfs import fetch_vault_deposit_data
from src.validators.typings import (
    BLSPrivkey,
    DepositData,
    KeeperApprovalParams,
    MultipleValidatorRegistration,
    NetworkValidator,
    Oracles,
    OraclesApproval,
    SingleValidatorRegistration,
    ValidatorsRoot,
)

VALIDATORS_REGISTRY_GENESIS_BLOCK: BlockNumber = NETWORK_CONFIG.VALIDATORS_REGISTRY_GENESIS_BLOCK
VAULT_GENESIS_BLOCK: BlockNumber = NETWORK_CONFIG.VAULT_GENESIS_BLOCK
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


class VaultValidatorsProcessor(EventProcessor):
    contract = vault_contract
    contract_event = 'ValidatorsRootUpdated'

    @staticmethod
    async def get_from_block() -> BlockNumber:
        last_root = get_last_validators_root()
        if not last_root:
            return VAULT_GENESIS_BLOCK

        return BlockNumber(last_root.block_number + 1)

    @staticmethod
    async def process_events(events: list[EventData]) -> None:
        if not events:
            return

        last_event = events[-1]
        new_root = ValidatorsRoot(
            root=Web3.to_hex(last_event['args']['validatorsRoot']),
            ipfs_hash=last_event['args']['validatorsIpfsHash'],
            block_number=BlockNumber(last_event['blockNumber'])
        )
        if not new_root.ipfs_hash:
            raise ValueError('Invalid validators root IPFS hash')

        deposit_data = await fetch_vault_deposit_data(new_root.ipfs_hash)
        save_deposit_data(deposit_data)
        save_validators_root(new_root)


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


@backoff.on_exception(backoff.expo, Exception, max_time=300)
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


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_available_assets() -> Wei:
    """Fetches vault's available assets for staking."""
    return await vault_contract.functions.availableAssets().call()


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_validators_registry_root() -> Bytes32:
    """Fetches the latest validators registry root."""
    return await validators_registry_contract.functions.get_deposit_root().call()


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_vault_validators_root() -> Bytes32:
    """Fetches vault's validators root."""
    return await vault_contract.functions.validatorsRoot().call()


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_available_deposit_data(
    private_keys: dict[HexStr, BLSPrivkey],
    validators_count: int
) -> tuple[list[DepositData], StandardMerkleTree | None]:
    """Fetches vault's available deposit data."""
    if validators_count <= 0:
        return [], None

    credentials = get_eth1_withdrawal_credentials(VAULT_CONTRACT_ADDRESS)
    current_index = await vault_contract.functions.validatorIndex().call()
    deposit_data = get_deposit_data()

    available_deposit_data = []
    current_count = 0
    leaves: list[tuple[bytes, int]] = []
    for data in deposit_data:
        leaves.append((_encode_tx_validator(credentials, data), data.validator_index))
        if data.validator_index < current_index or validators_count <= current_count:
            continue

        if data.public_key not in private_keys:
            logger.warning(
                'Cannot find validator with public key %s in imported keystores.',
                data.public_key
            )
            continue

        if is_validator_registered(data.public_key):
            logger.warning(
                'Validator with public key %s is already registered.'
                ' You must upload new deposit data.',
                data.public_key
            )
            continue

        available_deposit_data.append(data)
        current_count += 1

    if not available_deposit_data:
        logger.warning(
            'Failed to find available validator. You must upload new deposit data.'
        )

    tree = StandardMerkleTree.of(leaves, ['bytes', 'uint256'])
    if tree.root != Web3.to_hex(await get_vault_validators_root()):
        raise RuntimeError("Reconstructed tree root and vault's validators root don't match")

    return available_deposit_data, tree


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_oracles() -> Oracles:
    """Fetches oracles config from the DAO's ENS text record."""
    events = await oracles_contract.events.ConfigUpdated.get_logs(from_block=0)
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
        addresses=addresses
    )


async def register_single_validator(
    deposit_data_tree: StandardMerkleTree,
    deposit_data: DepositData,
    approval: OraclesApproval
) -> None:
    """Registers single validator."""
    if NETWORK not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    credentials = get_eth1_withdrawal_credentials(VAULT_CONTRACT_ADDRESS)
    validator = _encode_tx_validator(credentials, deposit_data)
    proof = deposit_data_tree.get_proof([validator, deposit_data.validator_index])  # type: ignore

    tx_data = SingleValidatorRegistration(
        keeperParams=KeeperApprovalParams(
            validatorsRegistryRoot=approval.validators_registry_root,
            validators=validator,
            signatures=approval.signatures,
            exitSignaturesIpfsHash=approval.ipfs_hash,
        ),
        proof=proof
    )
    tx = await vault_contract.functions.registerValidator(
        dataclasses.asdict(tx_data)
    ).transact()  # type: ignore
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)  # type: ignore


async def register_multiple_validator(
    deposit_data_tree: StandardMerkleTree,
    deposit_data: list[DepositData],
    approval: OraclesApproval
) -> None:
    """Registers multiple validators."""
    if NETWORK not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    credentials = get_eth1_withdrawal_credentials(VAULT_CONTRACT_ADDRESS)
    deposit_data = sorted(deposit_data, key=lambda d: d.validator_index)
    validators: list[bytes] = []
    leaves: list[tuple[bytes, int]] = []
    for deposit in deposit_data:
        validator = _encode_tx_validator(credentials, deposit)
        validators.append(validator)
        leaves.append((validator, deposit.validator_index))

    multi_proof = deposit_data_tree.get_multi_proof(leaves)
    sorted_validators = [v[0] for v in multi_proof.leaves]
    indexes = [sorted_validators.index(v) for v in validators]
    tx_data = MultipleValidatorRegistration(
        keeperParams=KeeperApprovalParams(
            validatorsRegistryRoot=approval.validators_registry_root,
            validators=b''.join(validators),
            signatures=approval.signatures,
            exitSignaturesIpfsHash=approval.ipfs_hash,
        ),
        indexes=indexes,
        proofFlags=multi_proof.proof_flags,
        proof=multi_proof.proof
    )
    tx = await vault_contract.functions.registerValidators(
        dataclasses.asdict(tx_data)
    ).transact()  # type: ignore
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)  # type: ignore


def _encode_tx_validator(
    withdrawal_credentials: bytes,
    deposit_data: DepositData
) -> bytes:
    public_key = Web3.to_bytes(hexstr=deposit_data.public_key)
    signature = Web3.to_bytes(hexstr=deposit_data.signature)
    deposit_root = compute_deposit_message(
        public_key=public_key,
        withdrawal_credentials=withdrawal_credentials,
        amount_gwei=DEPOSIT_AMOUNT_GWEI
    ).hash_tree_root
    return public_key + signature + deposit_root
