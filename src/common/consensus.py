from sw_utils import get_chain_epoch_head as sw_get_chain_epoch_head
from sw_utils import get_chain_finalized_head as sw_get_chain_finalized_head
from sw_utils.typings import ChainHead

from src.common.clients import consensus_client, execution_client
from src.config.settings import settings


async def get_chain_finalized_head() -> ChainHead:
    return await sw_get_chain_finalized_head(
        slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH,
        consensus_client=consensus_client,
    )


async def get_chain_epoch_head(epoch: int) -> ChainHead:
    """Fetches the epoch chain head."""
    return await sw_get_chain_epoch_head(
        epoch=epoch,
        slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH,
        consensus_client=consensus_client,
        execution_client=execution_client,
    )
