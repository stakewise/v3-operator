import logging
import struct
from multiprocessing import Pool
from typing import Set

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import EventProcessor, EventScanner, is_valid_deposit_data_signature
from web3 import Web3
from web3.types import EventData, Wei

from src.common.app_state import AppState
from src.common.clients import execution_non_retry_client
from src.common.contracts import (
    ValidatorsRegistryContract,
    VaultContract,
    multicall_contract,
    validators_registry_contract,
)
from src.common.typings import HarvestParams
from src.config.settings import settings
from src.harvest.execution import get_update_state_calls
from src.validators.database import (
    CheckpointCrud,
    NetworkValidatorCrud,
    VaultValidatorCrud,
)
from src.validators.typings import NetworkValidator, VaultValidator

logger = logging.getLogger(__name__)


class NetworkValidatorsProcessor(EventProcessor):
    contract_event = 'DepositEvent'

    def __init__(self) -> None:
        self.contract = ValidatorsRegistryContract(
            execution_client=execution_non_retry_client
        ).contract

    async def get_from_block(self) -> BlockNumber:
        app_state = AppState()
        if app_state.network_validators_block is not None:
            return BlockNumber(app_state.network_validators_block + 1)
        last_validator = NetworkValidatorCrud().get_last_network_validator()
        if not last_validator:
            return settings.network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK

        return BlockNumber(last_validator.block_number + 1)

    # pylint: disable-next=unused-argument
    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators = process_network_validator_events(events)
        NetworkValidatorCrud().save_network_validators(validators)
        AppState().network_validators_block = to_block


class NetworkValidatorsStartupProcessor(NetworkValidatorsProcessor):
    """Use multiprocessing event processor"""

    # pylint: disable-next=unused-argument
    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators = process_network_validator_events_multiprocessing(events)
        NetworkValidatorCrud().save_network_validators(validators)
        AppState().network_validators_block = to_block


def process_network_validator_events_multiprocessing(
    events: list[EventData],
) -> list[NetworkValidator]:
    """
    Processes `ValidatorsRegistry` registration events
    and returns the list of valid validators.
    Use multiprocessing to speed up operator startup.
    """
    with Pool(processes=settings.concurrency) as pool:
        results = [
            pool.apply_async(
                process_network_validator_event,
                [event, settings.network_config.GENESIS_FORK_VERSION],
            )
            for event in events
        ]
        for result in results:
            result.wait()
        validators = [result.get() for result in results]
        return [val for val in validators if val]


def process_network_validator_events(events: list[EventData]) -> list[NetworkValidator]:
    """
    Processes `ValidatorsRegistry` registration events
    and returns the list of valid validators.
    Multiprocessing version works slowly on small blocks ranges.
    """
    result: list[NetworkValidator] = []
    for event in events:
        validator = process_network_validator_event(
            event, settings.network_config.GENESIS_FORK_VERSION
        )
        if not validator:
            continue

        result.append(validator)

    return result


class VaultValidatorsProcessor(EventProcessor):
    contract_event = 'ValidatorRegistered'
    vault_address: ChecksumAddress

    def __init__(self, vault_address: ChecksumAddress) -> None:
        self.vault_address = vault_address
        self.contract = VaultContract(
            address=vault_address, execution_client=execution_non_retry_client
        ).contract

    async def get_from_block(self) -> BlockNumber:
        checkpoint = CheckpointCrud().get_vault_validators_checkpoint()
        if not checkpoint:
            return settings.network_config.KEEPER_GENESIS_BLOCK

        return BlockNumber(checkpoint + 1)

    # pylint: disable-next=unused-argument
    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators = [
            VaultValidator(
                public_key=Web3.to_hex(event['args']['publicKey']),
                block_number=BlockNumber(event['blockNumber']),
            )
            for event in events
        ]
        VaultValidatorCrud().save_vault_validators(validators)


class VaultV2ValidatorsProcessor(VaultValidatorsProcessor):
    contract_event = 'V2ValidatorRegistered'

    async def get_from_block(self) -> BlockNumber:
        checkpoint = CheckpointCrud().get_vault_v2_validators_checkpoint()
        if not checkpoint:
            return settings.network_config.KEEPER_GENESIS_BLOCK

        return BlockNumber(checkpoint + 1)


async def get_validators_start_index() -> int:
    latest_public_keys = await get_latest_network_validator_public_keys()
    validators_start_index = NetworkValidatorCrud().get_next_validator_index(
        list(latest_public_keys)
    )
    return validators_start_index


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
        validator = process_network_validator_event(
            event, settings.network_config.GENESIS_FORK_VERSION
        )
        if validator:
            new_public_keys.add(validator.public_key)

    return new_public_keys


async def get_latest_vault_v2_validator_public_keys(vault_address: ChecksumAddress) -> Set[HexStr]:
    """Fetches the latest vault v2 validator public keys registered after finalized block"""
    block_number = CheckpointCrud().get_vault_v2_validators_checkpoint()
    if block_number:
        from_block = BlockNumber(block_number + 1)
    else:
        from_block = settings.network_config.KEEPER_GENESIS_BLOCK
    vault_contract = VaultContract(vault_address)
    events = await vault_contract.events.V2ValidatorRegistered.get_logs(fromBlock=from_block)
    return {Web3.to_hex(event['args']['publicKey']) for event in events}


def process_network_validator_event(
    event: EventData, fork_version: bytes
) -> NetworkValidator | None:
    """
    Processes validator deposit event
    and returns its public key if the deposit is valid.
    """
    public_key = event['args']['pubkey']
    withdrawal_creds = event['args']['withdrawal_credentials']
    amount = struct.unpack('<Q', event['args']['amount'])[0]
    signature = event['args']['signature']
    if is_valid_deposit_data_signature(
        public_key, withdrawal_creds, signature, amount, fork_version
    ):
        return NetworkValidator(
            public_key=Web3.to_hex(public_key), block_number=BlockNumber(event['blockNumber'])
        )
    return None


async def get_withdrawable_assets(harvest_params: HarvestParams | None) -> Wei:
    """Fetches vault's available assets for staking."""
    vault_contract = VaultContract(settings.vault)
    if harvest_params is None:
        return await vault_contract.functions.withdrawableAssets().call()

    calls = await get_update_state_calls(
        vault_address=vault_contract.contract_address, harvest_params=harvest_params
    )
    withdrawable_assets_call = vault_contract.encode_abi(fn_name='withdrawableAssets', args=[])
    calls.append((vault_contract.contract_address, withdrawable_assets_call))

    _, multicall = await multicall_contract.aggregate(calls)
    return Wei(Web3.to_int(multicall[-1]))


async def scan_validators_events(block_number: BlockNumber, is_startup: bool) -> None:
    """Scans new vault and network validators for the given block number."""
    network_validators_processor: NetworkValidatorsStartupProcessor | NetworkValidatorsProcessor
    if is_startup:
        network_validators_processor = NetworkValidatorsStartupProcessor()
    else:
        network_validators_processor = NetworkValidatorsProcessor()

    network_validators_scanner = EventScanner(network_validators_processor)
    await network_validators_scanner.process_new_events(block_number)
    vault_validators_processor = VaultValidatorsProcessor(settings.vault)
    vault_validators_scanner = EventScanner(vault_validators_processor)
    await vault_validators_scanner.process_new_events(block_number)

    vault_v2_validators_processor = VaultV2ValidatorsProcessor(settings.vault)
    vault_v2_validators_scanner = EventScanner(vault_v2_validators_processor)
    await vault_v2_validators_scanner.process_new_events(block_number)

    CheckpointCrud().update_vault_checkpoints(block_number=block_number)
