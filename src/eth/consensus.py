import logging
from typing import Any, Dict

import backoff
from web3.beacon import AsyncBeacon

from src.common.utils import Singleton
from src.config.settings import CONSENSUS_ENDPOINT

logger = logging.getLogger(__name__)


class ConsensusClient(metaclass=Singleton):
    beacon: AsyncBeacon | None = None

    async def get_client(self) -> AsyncBeacon:
        if self.beacon:
            return self.beacon

        logger.info('Create Consensus client with endpoint=%s', CONSENSUS_ENDPOINT)

        self.beacon = AsyncBeacon(base_url=CONSENSUS_ENDPOINT)
        return self.beacon


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_genesis() -> Dict:
    """Fetches genesis."""
    client = await ConsensusClient().get_client()
    request = await client.get_genesis()
    return request['data']


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_validator(
    validator_id: str,
    state_id: str = 'head',
) -> Dict:
    """Fetches validators."""
    if not validator_id:
        return {}
    client = await ConsensusClient().get_client()
    request = await client.get_validator(
        validator_id=validator_id,
        state_id=state_id,
    )
    return request['data']


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_finality_checkpoints(state_id: str = 'head') -> Dict:
    """Fetches finality checkpoints."""
    client = await ConsensusClient().get_client()
    request = await client.get_finality_checkpoint(state_id)
    return request['data']
