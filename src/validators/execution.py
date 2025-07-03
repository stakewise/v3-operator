import logging
import struct
from multiprocessing import Pool
from typing import Set

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import EventProcessor, EventScanner, is_valid_deposit_data_signature
from web3 import Web3
from web3.types import EventData, Wei

from src.common.clients import execution_non_retry_client
from src.common.contracts import (
    ValidatorsRegistryContract,
    VaultContract,
    multicall_contract,
    validators_registry_contract,
)
from src.common.typings import HarvestParams
from src.config.settings import MIN_ACTIVATION_BALANCE, settings
from src.harvest.execution import get_update_state_calls
from src.validators.database import NetworkValidatorCrud, VaultCrud, VaultValidatorCrud
from src.validators.typings import NetworkValidator, VaultValidator

logger = logging.getLogger(__name__)


class NetworkValidatorsProcessor(EventProcessor):
    contract_event = 'DepositEvent'

    def __init__(self) -> None:
        self.contract = ValidatorsRegistryContract(
            execution_client=execution_non_retry_client
        ).contract

    async def get_from_block(self) -> BlockNumber:
        last_validator = NetworkValidatorCrud().get_last_network_validator()
        if not last_validator:
            return settings.network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK

        return BlockNumber(last_validator.block_number + 1)

    # pylint: disable-next=unused-argument
    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators = process_network_validator_events(events)
        NetworkValidatorCrud().save_network_validators(validators)


class NetworkValidatorsStartupProcessor(NetworkValidatorsProcessor):
    """Use multiprocessing event processor"""

    # pylint: disable-next=unused-argument
    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators = process_network_validator_events_multiprocessing(events)
        NetworkValidatorCrud().save_network_validators(validators)


def process_network_validator_events_multiprocessing(
    events: list[EventData],
) -> list[NetworkValidator]:
    """
    Processes `ValidatorsRegistry` registration events
    and returns the list of valid validators.
    Use multiprocessing to speed up operator startup.
    """
    with Pool(processes=settings.pool_size) as pool:
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
        checkpoint = VaultCrud().get_vault_validators_checkpoint(self.vault_address)
        if not checkpoint:
            return settings.network_config.KEEPER_GENESIS_BLOCK

        return BlockNumber(checkpoint + 1)

    # pylint: disable-next=unused-argument
    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators = [
            VaultValidator(
                vault_address=self.vault_address,
                public_key=Web3.to_hex(event['args']['publicKey']),
                block_number=BlockNumber(event['blockNumber']),
            )
            for event in events
        ]
        VaultValidatorCrud().save_vault_validators(validators)


class VaultV2ValidatorsProcessor(VaultValidatorsProcessor):
    contract_event = 'V2ValidatorRegistered'

    async def get_from_block(self) -> BlockNumber:
        checkpoint = VaultCrud().get_vault_v2_validators_checkpoint(self.vault_address)
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

    new_events = await validators_registry_contract.events.DepositEvent.get_logs(  # type: ignore
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


async def get_withdrawable_assets(
    vault_address: ChecksumAddress, harvest_params: HarvestParams | None
) -> Wei:
    """Fetches vault's available assets for staking."""
    vault_contract = VaultContract(vault_address)
    before_update_assets = await vault_contract.functions.withdrawableAssets().call()

    if harvest_params is None:
        return before_update_assets

    calls = await get_update_state_calls(
        vault_address=vault_contract.contract_address, harvest_params=harvest_params
    )
    withdrawable_assets_call = vault_contract.encode_abi(fn_name='withdrawableAssets', args=[])
    calls.append((vault_contract.contract_address, withdrawable_assets_call))

    _, multicall = await multicall_contract.aggregate(calls)
    after_update_assets = Web3.to_int(multicall[-1])

    before_update_validators = before_update_assets // MIN_ACTIVATION_BALANCE
    after_update_validators = after_update_assets // MIN_ACTIVATION_BALANCE
    if before_update_validators != after_update_validators:
        return Wei(after_update_assets)

    return Wei(before_update_assets)


async def scan_validators_events(block_number: BlockNumber, is_startup: bool) -> None:
    """Scans new vault and network validators for the given block number."""
    network_validators_processor: NetworkValidatorsStartupProcessor | NetworkValidatorsProcessor
    if is_startup:
        network_validators_processor = NetworkValidatorsStartupProcessor()
    else:
        network_validators_processor = NetworkValidatorsProcessor()

    network_validators_scanner = EventScanner(network_validators_processor)
    await network_validators_scanner.process_new_events(block_number)
    for vault in settings.vaults:
        vault_validators_processor = VaultValidatorsProcessor(vault_address=vault)
        vault_validators_scanner = EventScanner(vault_validators_processor)
        await vault_validators_scanner.process_new_events(block_number)

        vault_v2_validators_processor = VaultV2ValidatorsProcessor(vault_address=vault)
        vault_v2_validators_scanner = EventScanner(vault_v2_validators_processor)
        await vault_v2_validators_scanner.process_new_events(block_number)

        VaultCrud().update_vault_checkpoints(vault_address=vault, block_number=block_number)
