import backoff
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.clients import consensus_client
from src.config.settings import DEFAULT_RETRY_TIME


@backoff.on_exception(backoff.expo, Exception, max_time=DEFAULT_RETRY_TIME)
async def get_consensus_fork(
) -> ConsensusFork:
    """Fetches current fork data."""
    fork_data = (await consensus_client.get_fork_data())['data']
    return ConsensusFork(
        version=Web3.to_bytes(hexstr=fork_data['current_version']), epoch=int(fork_data['epoch'])
    )
