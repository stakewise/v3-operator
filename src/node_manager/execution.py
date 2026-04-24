import logging

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from hexbytes import HexBytes
from sw_utils import EventProcessor, EventScanner
from web3 import Web3
from web3.types import EventData

from src.common.clients import (
    execution_client,
    execution_non_retry_client,
    ipfs_fetch_client,
)
from src.common.contracts import NodesManagerContract, NodesManagerEncoder
from src.common.execution import transaction_gas_wrapper
from src.common.typings import HarvestParams
from src.config.settings import settings
from src.node_manager.typings import OperatorStateUpdateParams
from src.validators.database import CheckpointCrud, VaultValidatorCrud
from src.validators.execution import (
    NetworkValidatorsProcessor,
    NetworkValidatorsStartupProcessor,
)
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

    async def process_events(self, events: list[EventData], to_block: BlockNumber) -> None:
        validators: list[VaultValidator] = []
        for event in events:
            public_keys_bytes: bytes = event['args']['publicKeys']
            block_number = BlockNumber(event['blockNumber'])
            for pub_key in _parse_public_keys(public_keys_bytes):
                validators.append(VaultValidator(public_key=pub_key, block_number=block_number))

        if validators:
            VaultValidatorCrud().save_vault_validators(validators)
        CheckpointCrud().update_validators_checkpoint(block_number=to_block)


async def scan_validators_events(
    operator_address: ChecksumAddress, block_number: BlockNumber, is_startup: bool
) -> None:
    """Scans new vault and network validators for the given block number."""
    network_validators_processor: NetworkValidatorsStartupProcessor | NetworkValidatorsProcessor
    if is_startup:
        network_validators_processor = NetworkValidatorsStartupProcessor()
    else:
        network_validators_processor = NetworkValidatorsProcessor()

    network_validators_scanner = EventScanner(network_validators_processor)
    await network_validators_scanner.process_new_events(block_number)

    operator_validators_processor = OperatorValidatorsProcessor(operator_address)
    operator_validators_scanner = EventScanner(
        operator_validators_processor, argument_filters={'operator': operator_address}
    )
    await operator_validators_scanner.process_new_events(block_number)


def _parse_public_keys(public_keys_bytes: bytes) -> list[HexStr]:
    """Parse concatenated 48-byte BLS public keys into hex strings."""
    result: list[HexStr] = []
    for i in range(0, len(public_keys_bytes), BLS_PUBLIC_KEY_LENGTH):
        key_bytes = public_keys_bytes[i : i + BLS_PUBLIC_KEY_LENGTH]
        result.append(Web3.to_hex(key_bytes))
    return result


async def fetch_operator_state_from_ipfs(
    ipfs_hash: str, operator_address: ChecksumAddress
) -> OperatorStateUpdateParams | None:
    """Fetch operator state data from IPFS and return update params if found."""
    ipfs_data = await ipfs_fetch_client.fetch_json(ipfs_hash)

    for operator_data in ipfs_data.get('operators', []):  # type: ignore
        address = Web3.to_checksum_address(operator_data['address'])
        if address != operator_address:
            continue

        return OperatorStateUpdateParams(
            total_assets=int(operator_data['totalAssets']),
            cum_penalty_assets=int(operator_data['cumPenaltyAssets']),
            cum_earned_fee_shares=int(operator_data['cumEarnedFeeShares']),
            proof=[HexBytes(Web3.to_bytes(hexstr=HexStr(p))) for p in operator_data['proof']],
        )

    return None


async def submit_state_sync_transaction(
    operator_address: ChecksumAddress,
    params: OperatorStateUpdateParams,
    harvest_params: HarvestParams | None = None,
) -> HexStr | None:
    """Submit updateOperatorState, optionally batched with updateVaultState via multicall."""
    node_manager_contract = NodesManagerContract()
    encoder = NodesManagerEncoder()

    if harvest_params is not None:
        calls: list[HexStr] = [
            encoder.update_vault_state(harvest_params),
            encoder.update_operator_state(operator_address, params),
        ]
        tx_function = node_manager_contract.contract.functions.multicall(calls)
    else:
        tx_function = node_manager_contract.contract.functions.updateOperatorState(
            operator_address,
            (
                params.total_assets,
                params.cum_penalty_assets,
                params.cum_earned_fee_shares,
                params.proof,
            ),
        )

    tx_hash = await transaction_gas_wrapper(tx_function)
    receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx_hash, timeout=settings.execution_transaction_timeout
    )

    if not receipt['status']:
        logger.error('State sync transaction failed: %s', Web3.to_hex(tx_hash))
        return None

    return Web3.to_hex(tx_hash)
