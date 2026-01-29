from eth_typing import BlockNumber, HexStr
from sw_utils import ChainHead
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import consensus_client, execution_client
from src.common.execution import fake_exponential
from src.common.typings import PendingPartialWithdrawal
from src.config.settings import settings
from src.validators.typings import ConsensusValidator


async def get_pending_partial_withdrawals(
    chain_head: ChainHead, consensus_validators: list[ConsensusValidator]
) -> list[PendingPartialWithdrawal]:
    """
    Get pending partial withdrawals from both consensus and execution layers.
    """
    consensus_withdrawals = await consensus_client.get_pending_partial_withdrawals(
        str(chain_head.slot)
    )
    indexes: set[int] = set()
    public_key_to_index: dict[HexStr, int] = {}
    for val in consensus_validators:
        indexes.add(val.index)
        public_key_to_index[val.public_key] = val.index

    result: list[PendingPartialWithdrawal] = []
    for withdrawal in consensus_withdrawals:
        validator_index = int(withdrawal['validator_index'])
        if validator_index not in indexes:
            continue

        result.append(
            PendingPartialWithdrawal(
                validator_index=validator_index, amount=Gwei(int(withdrawal['amount']))
            )
        )

    execution_withdrawals = await get_execution_partial_withdrawals(chain_head.block_number)
    for withdrawal in execution_withdrawals:
        public_key = withdrawal['public_key']
        if public_key not in public_key_to_index:
            continue

        result.append(
            PendingPartialWithdrawal(
                validator_index=public_key_to_index[public_key], amount=Gwei(withdrawal['amount'])
            )
        )

    return result


async def get_execution_partial_withdrawals(block_number: BlockNumber | None = None) -> list[dict]:
    queue_head_index_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_QUEUE_HEAD_STORAGE_SLOT,
        block_identifier=block_number,
    )
    queue_head_index = Web3.to_int(queue_head_index_bytes)

    queue_tail_index_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_QUEUE_TAIL_STORAGE_SLOT,
        block_identifier=block_number,
    )
    queue_tail_index = Web3.to_int(queue_tail_index_bytes)
    queue_length = queue_tail_index - queue_head_index

    execution_withdrawals = []
    for i in range(queue_length):
        queue_storage_slot = (
            settings.network_config.EXECUTION_REQUEST_QUEUE_STORAGE_OFFSET
            + (queue_head_index + i) * 3
        )
        storage_slot0 = await execution_client.eth.get_storage_at(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            queue_storage_slot,
            block_identifier=block_number,
        )
        storage_slot1 = await execution_client.eth.get_storage_at(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            queue_storage_slot + 1,
            block_identifier=block_number,
        )
        storage_slot2 = await execution_client.eth.get_storage_at(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            queue_storage_slot + 2,
            block_identifier=block_number,
        )
        execution_withdrawals.append(
            {
                'source_address': Web3.to_checksum_address(storage_slot0[12:32]),
                'public_key': Web3.to_hex(storage_slot1[0:32] + storage_slot2[0:16]),
                'amount': int.from_bytes(storage_slot2[16:24]),
            }
        )

    return execution_withdrawals


async def get_withdrawal_request_fee(count: int = 1, gap_count: int = 10) -> Wei:
    """
    Calculates the current withdrawal request fee.
    For more details see: https://eips.ethereum.org/EIPS/eip-7002
    """
    previous_excess_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        settings.network_config.EXCESS_EXECUTION_REQUESTS_STORAGE_SLOT,
    )
    previous_excess = Web3.to_int(previous_excess_bytes)

    count += await get_execution_withdrawals_count()
    count += gap_count

    excess = 0
    target_withdrawal_requests_per_block = (
        settings.network_config.TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK
    )
    if previous_excess + count > target_withdrawal_requests_per_block:
        excess = previous_excess + count - target_withdrawal_requests_per_block

    per_validator_fee = fake_exponential(
        settings.network_config.MIN_EXECUTION_REQUEST_FEE,
        excess,
        settings.network_config.EXECUTION_REQUEST_FEE_UPDATE_FRACTION,
    )
    return Wei(per_validator_fee)


async def get_withdrawals_count(chain_head: ChainHead) -> int:
    count = await get_execution_withdrawals_count(chain_head.block_number)
    pending_partial_withdrawals = await consensus_client.get_pending_partial_withdrawals(
        str(chain_head.slot)
    )
    return len(pending_partial_withdrawals) + count


async def get_execution_withdrawals_count(block_number: BlockNumber | None = None) -> int:
    count_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_COUNT_STORAGE_SLOT,
        block_identifier=block_number,
    )
    return Web3.to_int(count_bytes)
