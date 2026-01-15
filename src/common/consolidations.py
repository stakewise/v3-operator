from eth_typing import BlockNumber, HexStr
from sw_utils import ChainHead
from web3 import Web3
from web3.types import Wei
from common.execution import fake_exponential

from src.common.clients import consensus_client, execution_client
from src.common.typings import PendingConsolidation
from src.config.settings import settings
from src.validators.typings import ConsensusValidator


async def get_pending_consolidations(
    chain_head: ChainHead, consensus_validators: list[ConsensusValidator]
) -> list[PendingConsolidation]:
    consensus_consolidations = await consensus_client.get_pending_consolidations(
        str(chain_head.slot)
    )
    indexes: set[int] = set()
    public_key_to_index: dict[HexStr, int] = {}
    for val in consensus_validators:
        indexes.add(val.index)
        public_key_to_index[val.public_key] = val.index

    result: list[PendingConsolidation] = []
    for cons in consensus_consolidations:
        source_index = int(cons['source_index'])
        target_index = int(cons['target_index'])

        has_source = source_index in indexes
        has_target = target_index in indexes
        if not has_source and not has_target:
            continue

        if has_source and not has_target:
            raise ValueError(f'Target validator index {target_index} not found in vault validators')

        result.append(PendingConsolidation(source_index=source_index, target_index=target_index))

    execution_consolidations = await get_execution_consolidations(chain_head.block_number)
    for cons in execution_consolidations:
        source_pubkey = cons['source_pubkey']
        target_pubkey = cons['target_pubkey']

        if source_pubkey not in public_key_to_index or target_pubkey not in public_key_to_index:
            continue

        source_index = public_key_to_index[source_pubkey]
        target_index = public_key_to_index[target_pubkey]
        result.append(PendingConsolidation(source_index=source_index, target_index=target_index))

    return result


async def get_execution_consolidations(block_number: BlockNumber | None = None) -> list[dict]:
    queue_head_index_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_QUEUE_HEAD_STORAGE_SLOT,
        block_identifier=block_number,
    )
    queue_head_index = Web3.to_int(queue_head_index_bytes)

    queue_tail_index_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_QUEUE_TAIL_STORAGE_SLOT,
        block_identifier=block_number,
    )
    queue_tail_index = Web3.to_int(queue_tail_index_bytes)
    queue_length = queue_tail_index - queue_head_index

    execution_consolidations = []
    for i in range(queue_length):
        queue_storage_slot = (
            settings.network_config.EXECUTION_REQUEST_QUEUE_STORAGE_OFFSET
            + (queue_head_index + i) * 4
        )
        storage_slot0 = await execution_client.eth.get_storage_at(
            settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
            queue_storage_slot,
            block_identifier=block_number,
        )
        storage_slot1 = await execution_client.eth.get_storage_at(
            settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
            queue_storage_slot + 1,
            block_identifier=block_number,
        )
        storage_slot2 = await execution_client.eth.get_storage_at(
            settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
            queue_storage_slot + 2,
            block_identifier=block_number,
        )
        storage_slot3 = await execution_client.eth.get_storage_at(
            settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
            queue_storage_slot + 3,
            block_identifier=block_number,
        )
        execution_consolidations.append(
            {
                'source_address': Web3.to_checksum_address(storage_slot0[12:32]),
                'source_pubkey': Web3.to_hex(storage_slot1[0:32] + storage_slot2[0:16]),
                'target_pubkey': Web3.to_hex(storage_slot2[16:32] + storage_slot3[0:32]),
            }
        )

    return execution_consolidations


async def get_consolidation_request_fee(count: int = 1, gap_count: int = 5) -> Wei:
    """
    Calculates the current consolidation request fee.
    For more details see: https://eips.ethereum.org/EIPS/eip-7251
    """
    previous_excess_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        settings.network_config.EXCESS_EXECUTION_REQUESTS_STORAGE_SLOT,
    )
    previous_excess = Web3.to_int(previous_excess_bytes)

    count += await get_execution_consolidations_count()
    count += gap_count

    excess = 0
    target_consolidation_requests_per_block = (
        settings.network_config.TARGET_CONSOLIDATION_REQUESTS_PER_BLOCK
    )
    if previous_excess + count > target_consolidation_requests_per_block:
        excess = previous_excess + count - target_consolidation_requests_per_block

    per_validator_fee = fake_exponential(
        settings.network_config.MIN_EXECUTION_REQUEST_FEE,
        excess,
        settings.network_config.EXECUTION_REQUEST_FEE_UPDATE_FRACTION,
    )
    return Wei(per_validator_fee)


async def get_consolidations_count(chain_head: ChainHead) -> int:
    count = await get_execution_consolidations_count(chain_head.block_number)
    consensus_consolidations = await consensus_client.get_pending_consolidations(
        str(chain_head.slot)
    )
    return len(consensus_consolidations) + count


async def get_execution_consolidations_count(block_number: BlockNumber | None = None) -> int:
    count_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_COUNT_STORAGE_SLOT,
        block_identifier=block_number,
    )
    return Web3.to_int(count_bytes)
