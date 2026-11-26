import logging
import struct
from multiprocessing import Pool
from typing import Set

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import (
    FAR_FUTURE_EPOCH,
    EventProcessor,
    EventScanner,
    is_valid_deposit_data_signature,
)
from web3 import Web3
from web3.types import EventData

from src.common.clients import execution_non_retry_client
from src.common.contracts import (
    ValidatorsRegistryContract,
    VaultContract,
    validators_registry_contract,
)
from src.common.utils import calc_slot_by_block_number
from src.config.settings import settings
from src.validators.database import (
    BuilderDepositCrud,
    CheckpointCrud,
    NetworkValidatorCrud,
    VaultValidatorCrud,
    transaction,
)
from src.validators.typings import BuilderDeposit, NetworkValidator, VaultValidator

BUILDER_WITHDRAWAL_PREFIX = b'\xb0'

logger = logging.getLogger(__name__)


class NetworkValidatorsProcessor(EventProcessor):
    contract_event = 'DepositEvent'

    def __init__(self) -> None:
        self.contract = ValidatorsRegistryContract(
            execution_client=execution_non_retry_client
        ).contract

    async def get_from_block(self) -> BlockNumber:
        return await get_network_validators_from_block()

    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators, builder_deposits = await self._process_deposit_events(events)
        _save_network_validator_events(validators, builder_deposits, to_block)

    async def _process_deposit_events(
        self, events: list[EventData]
    ) -> tuple[list[NetworkValidator], list[BuilderDeposit]]:
        return await process_network_validator_events(events)


class NetworkValidatorsStartupProcessor(NetworkValidatorsProcessor):
    """Use multiprocessing event processor"""

    async def _process_deposit_events(
        self, events: list[EventData]
    ) -> tuple[list[NetworkValidator], list[BuilderDeposit]]:
        return await process_network_validator_events_multiprocessing(events)


class VaultValidatorsProcessor(EventProcessor):
    contract_event = 'ValidatorRegistered'
    vault_address: ChecksumAddress

    def __init__(self, vault_address: ChecksumAddress) -> None:
        self.vault_address = vault_address
        self.contract = VaultContract(
            address=vault_address, execution_client=execution_non_retry_client
        ).contract

    async def get_from_block(self) -> BlockNumber:
        checkpoint = CheckpointCrud().get_validators_checkpoint()
        if checkpoint is not None:
            return BlockNumber(checkpoint + 1)

        return settings.network_config.KEEPER_GENESIS_BLOCK

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
        checkpoint = CheckpointCrud().get_validators_checkpoint()
        if checkpoint is not None:
            return BlockNumber(checkpoint + 1)

        return _v2_validators_genesis_block()


async def get_latest_deposits() -> tuple[Set[HexStr], list[BuilderDeposit]]:
    """
    Processes deposit events not yet saved by the scanner.
    Returns public keys of new validators and builder deposits affecting validator index.
    """
    from_block = await get_network_validators_from_block()
    new_events = await validators_registry_contract.get_deposit_events(from_block=from_block)
    new_validators, builder_deposits = await process_network_validator_events(new_events)
    builder_deposits = _exclude_counted_builder_deposits(
        builder_deposits, validators=new_validators, crud=NetworkValidatorCrud()
    )
    return {v.public_key for v in new_validators}, builder_deposits


async def get_network_validators_from_block() -> BlockNumber:
    """
    Returns the block to start scanning deposit events from.
    The explicit checkpoint is not derived from the last validator: it advances over blocks
    without validators, and builder deposits resolved at the fork may remove the last ones.
    """
    checkpoint = CheckpointCrud().get_checkpoint(CheckpointCrud.CHECKPOINT_NETWORK_VALIDATORS)
    if checkpoint is not None:
        return BlockNumber(checkpoint + 1)

    # Fallback for databases created before the checkpoint was introduced
    last_validator = NetworkValidatorCrud().get_last_network_validator()
    if not last_validator:
        return settings.network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK

    checkpoints = settings.network_config.CHECKPOINTS
    return BlockNumber(
        max(last_validator.block_number, checkpoints.GENESIS_VALIDATORS_LAST_BLOCK) + 1
    )


async def process_network_validator_events(
    events: list[EventData],
) -> tuple[list[NetworkValidator], list[BuilderDeposit]]:
    """
    Processes `ValidatorsRegistry` deposit events.
    Returns valid validators and builder deposits.
    Multiprocessing version works slowly on small blocks ranges.

    A valid deposit with builder withdrawal credentials (0xB0):
    - made before Glamsterdam is a builder deposit, not a validator:
      - processed by the consensus layer before the fork, it takes a validator index
      - still pending at the fork, it is onboarded as a builder,
        see `onboard_builders_from_pending_deposits` in the Gloas fork spec
      Builder deposits are resolved at the fork, see `src.validators.builders_onboarding`.
    - made after Glamsterdam is a regular validator deposit
    """
    parsed_validators = [
        process_network_validator_event(event, settings.network_config.GENESIS_FORK_VERSION)
        for event in events
    ]
    return await _split_builder_deposits(events, parsed_validators)


async def process_network_validator_events_multiprocessing(
    events: list[EventData],
) -> tuple[list[NetworkValidator], list[BuilderDeposit]]:
    """
    Same as `process_network_validator_events`.
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
        parsed_validators = [result.get() for result in results]
    return await _split_builder_deposits(events, parsed_validators)


async def get_latest_vault_v2_validator_public_keys(vault_address: ChecksumAddress) -> Set[HexStr]:
    """Fetches the latest vault v2 validator public keys registered after finalized block"""
    checkpoint = CheckpointCrud().get_validators_checkpoint()
    if checkpoint is not None:
        from_block = BlockNumber(checkpoint + 1)
    else:
        from_block = _v2_validators_genesis_block()
    vault_contract = VaultContract(vault_address)
    public_keys = await vault_contract.get_v2_validator_registered_public_keys(
        from_block=from_block
    )
    return set(public_keys)


def _v2_validators_genesis_block() -> BlockNumber:
    """The earliest block a `V2ValidatorRegistered` event can appear at."""
    network_config = settings.network_config
    return BlockNumber(max(network_config.KEEPER_GENESIS_BLOCK, network_config.PECTRA_BLOCK))


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


async def scan_validators_events(block_number: BlockNumber, is_startup: bool) -> None:
    """Scans new vault and network validators for the given block number."""
    network_validators_processor: NetworkValidatorsStartupProcessor | NetworkValidatorsProcessor
    if is_startup:
        network_validators_processor = NetworkValidatorsStartupProcessor()
    else:
        network_validators_processor = NetworkValidatorsProcessor()

    network_validators_scanner = create_event_scanner(network_validators_processor)
    await network_validators_scanner.process_new_events(block_number)
    vault_validators_processor = VaultValidatorsProcessor(settings.vault)
    vault_validators_scanner = create_event_scanner(vault_validators_processor)
    await vault_validators_scanner.process_new_events(block_number)

    vault_v2_validators_processor = VaultV2ValidatorsProcessor(settings.vault)
    vault_v2_validators_scanner = create_event_scanner(vault_v2_validators_processor)
    await vault_v2_validators_scanner.process_new_events(block_number)

    CheckpointCrud().update_validators_checkpoint(block_number=block_number)


def create_event_scanner(processor: EventProcessor) -> EventScanner:
    return EventScanner(processor, max_chunk_size=settings.event_scanner_max_chunk_size)


def _save_network_validator_events(
    validators: list[NetworkValidator],
    builder_deposits: list[BuilderDeposit],
    to_block: BlockNumber,
) -> None:
    with transaction() as connection:
        network_validator_crud = NetworkValidatorCrud(connection)
        network_validator_crud.save_network_validators(validators)

        builder_deposits = _exclude_counted_builder_deposits(
            builder_deposits, validators=validators, crud=network_validator_crud
        )
        if builder_deposits:
            logger.warning(
                'Found %d builder deposit(s) made before Glamsterdam: %s. '
                'Validator approvals are blocked until the Glamsterdam fork.',
                len(builder_deposits),
                [d.public_key for d in builder_deposits],
            )
        BuilderDepositCrud(connection).save_builder_deposits(builder_deposits)

        CheckpointCrud(connection).update_checkpoint(
            CheckpointCrud.CHECKPOINT_NETWORK_VALIDATORS, to_block
        )


def _exclude_counted_builder_deposits(
    builder_deposits: list[BuilderDeposit],
    validators: list[NetworkValidator],
    crud: NetworkValidatorCrud,
) -> list[BuilderDeposit]:
    """
    Leaves out builder deposits for public keys that are already counted as validators:
    such a deposit tops up the validator, so the validator index is not affected.
    """
    counted_public_keys = {v.public_key for v in validators}
    counted_public_keys |= crud.get_registered_public_keys([d.public_key for d in builder_deposits])
    return [d for d in builder_deposits if d.public_key not in counted_public_keys]


async def _split_builder_deposits(
    events: list[EventData], parsed_validators: list[NetworkValidator | None]
) -> tuple[list[NetworkValidator], list[BuilderDeposit]]:
    """
    Splits valid deposits into validators and builder deposits.
    Runs in the main process: the fork check calls the execution client.
    """
    validators: list[NetworkValidator] = []
    builder_deposits: list[BuilderDeposit] = []
    for event, validator in zip(events, parsed_validators):
        if validator is None:
            continue

        if _is_builder_withdrawal_credentials(
            event['args']['withdrawal_credentials']
        ) and not await _is_glamsterdam_block(validator.block_number):
            builder_deposits.append(
                BuilderDeposit(public_key=validator.public_key, block_number=validator.block_number)
            )
            continue

        validators.append(validator)

    return validators, builder_deposits


def _is_builder_withdrawal_credentials(withdrawal_credentials: bytes) -> bool:
    return withdrawal_credentials[:1] == BUILDER_WITHDRAWAL_PREFIX


async def _is_glamsterdam_block(block_number: BlockNumber) -> bool:
    """Whether the execution block is processed by Glamsterdam consensus rules."""
    if settings.network_config.GLAMSTERDAM_EPOCH == FAR_FUTURE_EPOCH:
        # Glamsterdam is not scheduled, skip the execution client call
        return False
    return await calc_slot_by_block_number(block_number) >= settings.network_config.GLAMSTERDAM_SLOT
