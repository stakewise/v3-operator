from sw_utils.typings import ChainHead

from src.common.clients import consensus_client
from src.config.settings import settings


async def get_chain_finalized_head() -> ChainHead:
    return await consensus_client.get_chain_finalized_head(settings.network_config.SLOTS_PER_EPOCH)
