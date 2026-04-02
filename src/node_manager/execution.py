import logging

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import EventProcessor, EventScanner
from web3 import Web3
from web3.types import EventData

from src.common.clients import execution_non_retry_client
from src.common.contracts import NodesManagerContract
from src.config.settings import settings
from src.validators.database import CheckpointCrud, VaultValidatorCrud
from src.validators.typings import VaultValidator

logger = logging.getLogger(__name__)

BLS_PUBLIC_KEY_LENGTH = 48


class OperatorValidatorsProcessor(EventProcessor):
    """Scans ValidatorsRegistered events from NodesManager filtered by operator."""

    contract_event = 'ValidatorsRegistered'

    def __init__(self, operator_address: ChecksumAddress) -> None:
        self.operator_address = operator_address
        self.contract = NodesManagerContract(execution_client=execution_non_retry_client).contract

    async def get_from_block(self) -> BlockNumber:
        checkpoint = CheckpointCrud().get_validators_checkpoint()
        if not checkpoint:
            return settings.network_config.NODES_MANAGER_GENESIS_BLOCK
        return BlockNumber(checkpoint + 1)

    # pylint: disable-next=unused-argument
    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators: list[VaultValidator] = []
        for event in events:
            if event['args']['operator'] != self.operator_address:
                continue
            public_keys_bytes: bytes = event['args']['publicKeys']
            block_number = BlockNumber(event['blockNumber'])
            for pub_key in _parse_public_keys(public_keys_bytes):
                validators.append(VaultValidator(public_key=pub_key, block_number=block_number))

        if validators:
            VaultValidatorCrud().save_vault_validators(validators)


async def scan_node_manager_validators_events(
    operator_address: ChecksumAddress,
    block_number: BlockNumber,
) -> None:
    """Scans NodesManager ValidatorsRegistered events for the given operator."""
    processor = OperatorValidatorsProcessor(operator_address)
    scanner = EventScanner(processor)
    await scanner.process_new_events(block_number)
    CheckpointCrud().update_validators_checkpoint(block_number)


def _parse_public_keys(public_keys_bytes: bytes) -> list[HexStr]:
    """Parse concatenated 48-byte BLS public keys into hex strings."""
    result: list[HexStr] = []
    for i in range(0, len(public_keys_bytes), BLS_PUBLIC_KEY_LENGTH):
        key_bytes = public_keys_bytes[i : i + BLS_PUBLIC_KEY_LENGTH]
        result.append(HexStr(Web3.to_hex(key_bytes)))
    return result
