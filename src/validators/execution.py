import logging
import struct
from multiprocessing import Pool
from typing import Sequence, Set

from eth_typing import BlockNumber, HexStr
from sw_utils import EventProcessor, is_valid_deposit_data_signature
from web3 import Web3
from web3.types import EventData, Wei

from src.common.clients import execution_non_retry_client
from src.common.contracts import (
    ValidatorsRegistryContract,
    multicall_contract,
    validators_registry_contract,
    vault_contract,
)
from src.common.typings import HarvestParams
from src.common.vault import Vault
from src.config.settings import DEPOSIT_AMOUNT, settings
from src.harvest.execution import get_update_state_calls
from src.validators.database import NetworkValidatorCrud
from src.validators.keystores.base import BaseKeystore
from src.validators.typings import DepositData, NetworkValidator, Validator

logger = logging.getLogger(__name__)


class NetworkValidatorsProcessor(EventProcessor):
    contract_event = 'DepositEvent'

    def __init__(self) -> None:
        self.contract = ValidatorsRegistryContract(
            execution_client=execution_non_retry_client
        ).contract

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


class NetworkValidatorsStartupProcessor(NetworkValidatorsProcessor):
    """Use multiprocessing event processor"""

    @staticmethod
    # pylint: disable-next=unused-argument
    async def process_events(events: list[EventData], to_block: BlockNumber) -> None:
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
    amount_gwei = struct.unpack('<Q', event['args']['amount'])[0]
    signature = event['args']['signature']
    if is_valid_deposit_data_signature(
        public_key, withdrawal_creds, signature, amount_gwei, fork_version
    ):
        return NetworkValidator(
            public_key=Web3.to_hex(public_key), block_number=BlockNumber(event['blockNumber'])
        )
    return None


async def get_withdrawable_assets(harvest_params: HarvestParams | None) -> Wei:
    """Fetches vault's available assets for staking."""
    before_update_assets = await vault_contract.functions.withdrawableAssets().call()

    if harvest_params is None:
        return before_update_assets

    calls = await get_update_state_calls(harvest_params)
    withdrawable_assets_call = vault_contract.encode_abi(fn_name='withdrawableAssets', args=[])
    calls.append((vault_contract.address, withdrawable_assets_call))

    _, multicall = await multicall_contract.aggregate(calls)
    after_update_assets = Web3.to_int(multicall[-1])

    before_update_validators = before_update_assets // DEPOSIT_AMOUNT
    after_update_validators = after_update_assets // DEPOSIT_AMOUNT
    if before_update_validators != after_update_validators:
        return Wei(after_update_assets)

    return Wei(before_update_assets)


async def get_validators_from_deposit_data(
    keystore: BaseKeystore | None,
    deposit_data: DepositData,
    count: int,
    run_check_deposit_data_root: bool = True,
) -> Sequence[Validator]:
    """Fetches vault's available validators."""
    if run_check_deposit_data_root:
        try:
            await check_deposit_data_root(deposit_data.tree.root)
        except RuntimeError:
            if settings.disable_deposit_data_warnings:
                return []
            raise

    start_index = await Vault().get_validators_index()
    validators: list[Validator] = []

    for validator in deposit_data.validators[start_index : start_index + count]:
        if keystore and validator.public_key not in keystore:
            if not settings.disable_deposit_data_warnings:
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


async def check_deposit_data_root(deposit_data_root: str) -> None:
    """Checks whether deposit data root matches validators root in Vault."""

    vault_deposit_data_root = await Vault().get_validators_root()
    if deposit_data_root != Web3.to_hex(vault_deposit_data_root):
        raise RuntimeError(
            "Deposit data tree root and vault's validators root don't match."
            ' Have you updated vault deposit data?'
        )
