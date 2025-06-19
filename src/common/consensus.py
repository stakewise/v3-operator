import logging

from sw_utils import get_chain_finalized_head as sw_get_chain_finalized_head
from sw_utils.typings import ChainHead

from src.common.clients import consensus_client
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def get_chain_finalized_head() -> ChainHead:
    return await sw_get_chain_finalized_head(
        consensus_client=consensus_client, slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH
    )
