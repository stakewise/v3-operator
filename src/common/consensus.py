from sw_utils import get_chain_finalized_head as sw_get_chain_finalized_head
from sw_utils.consensus import get_chain_epoch_head as sw_get_chain_epoch_head
from sw_utils.consensus import get_chain_justified_head as sw_get_chain_justified_head
from sw_utils.consensus import get_chain_latest_head as sw_get_chain_latest_head
from sw_utils.typings import ChainHead

from src.common.clients import consensus_client, execution_client
from src.config.settings import settings


async def get_chain_finalized_head() -> ChainHead:
    return await sw_get_chain_finalized_head(
        consensus_client=consensus_client, slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH
    )


async def get_chain_justified_head() -> ChainHead:
    return await sw_get_chain_justified_head(
        consensus_client=consensus_client, slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH
    )


async def get_chain_latest_head() -> ChainHead:
    return await sw_get_chain_latest_head(
        consensus_client=consensus_client, slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH
    )


async def get_get_chain_epoch_head(epoch: int) -> ChainHead:
    return await sw_get_chain_epoch_head(
        epoch=epoch,
        consensus_client=consensus_client,
        execution_client=execution_client,
        slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH,
    )
