from aiohttp import ClientResponseError
from eth_typing import BlockNumber
from sw_utils.typings import ChainHead
from web3.exceptions import BlockNotFound
from web3.types import Timestamp

from src.common.clients import consensus_client, execution_client
from src.config.settings import settings


async def get_chain_finalized_head() -> ChainHead:
    return await consensus_client.get_chain_finalized_head(settings.network_config.SLOTS_PER_EPOCH)


async def get_chain_epoch_head(epoch: int) -> ChainHead:
    """Fetches the epoch chain head."""
    network_config = settings.network_config
    slot_id: int = (epoch * network_config.SLOTS_PER_EPOCH) + network_config.SLOTS_PER_EPOCH - 1
    for i in range(network_config.SLOTS_PER_EPOCH):
        try:
            slot = await consensus_client.get_block(str(slot_id - i))
        except ClientResponseError as e:
            if hasattr(e, 'status') and e.status == 404:
                # slot was not proposed, try the previous one
                continue
            raise e
        try:
            execution_payload = slot['data']['message']['body']['execution_payload']
            return ChainHead(
                epoch=epoch,
                consensus_block=slot_id - i,
                execution_block=BlockNumber(int(execution_payload['block_number'])),
                execution_ts=Timestamp(int(execution_payload['timestamp'])),
            )
        except KeyError:  # pre shapella slot
            block_hash = slot['data']['message']['body']['eth1_data']['block_hash']
            try:
                block = await execution_client.eth.get_block(block_hash)
            except BlockNotFound:
                continue

            return ChainHead(
                epoch=epoch,
                consensus_block=slot_id - i,
                execution_block=BlockNumber(int(block['number'])),
                execution_ts=Timestamp(int(block['timestamp'])),
            )

    raise RuntimeError(f'Failed to fetch slot for epoch {epoch}')
