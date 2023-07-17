from sw_utils.decorators import retry_aiohttp_errors

from src.common.clients import consensus_client
from src.config.settings import DEFAULT_RETRY_TIME


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def get_validators(validator_ids: list[str]) -> dict:
    """Fetches validators with retry."""
    return await consensus_client.get_validators_by_ids(validator_ids)
