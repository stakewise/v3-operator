from dataclasses import dataclass

from aiohttp import ClientResponseError
from eth_typing import BlockNumber
from sw_utils.decorators import retry_aiohttp_errors
from sw_utils.typings import ConsensusFork
from web3 import Web3
from web3.types import Timestamp

from src.common.clients import consensus_client
from src.common.metrics import metrics
from src.config.settings import DEFAULT_RETRY_TIME, settings


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def get_consensus_fork() -> ConsensusFork:
    """Fetches current fork data."""
    fork_data = (await consensus_client.get_fork_data())['data']
    return ConsensusFork(
        version=Web3.to_bytes(hexstr=fork_data['current_version']), epoch=int(fork_data['epoch'])
    )


@dataclass
class ChainHead:
    epoch: int
    consensus_block: int
    execution_block: BlockNumber
    execution_ts: Timestamp


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def get_chain_finalized_head() -> ChainHead:
    """Fetches the fork safe chain head."""
    checkpoints = await consensus_client.get_finality_checkpoint()
    epoch: int = int(checkpoints['data']['finalized']['epoch'])
    slots_per_epoch = settings.network_config.SLOTS_PER_EPOCH
    last_slot_id: int = (epoch * slots_per_epoch) + slots_per_epoch - 1
    metrics.slot_number.set(last_slot_id)
    for i in range(slots_per_epoch):
        try:
            slot = await consensus_client.get_block(last_slot_id - i)
        except ClientResponseError as e:
            if hasattr(e, 'status') and e.status == 404:
                # slot was not proposed, try the previous one
                continue
            raise e

        execution_payload = slot['data']['message']['body']['execution_payload']
        return ChainHead(
            epoch=epoch,
            consensus_block=last_slot_id - i,
            execution_block=BlockNumber(int(execution_payload['block_number'])),
            execution_ts=Timestamp(int(execution_payload['timestamp'])),
        )

    raise RuntimeError(f'Failed to fetch slot for epoch {epoch}')
