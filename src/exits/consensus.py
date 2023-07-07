from sw_utils.decorators import retry_aiohttp_errors
from web3.types import HexStr

from src.common.clients import consensus_client
from src.config.settings import DEFAULT_RETRY_TIME, settings


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def get_validator_public_keys(validator_indexes: list[int]) -> dict[int, HexStr]:
    """Fetches validators public keys."""
    indexes = [str(index) for index in validator_indexes]
    result = {}
    for i in range(0, len(indexes), settings.VALIDATORS_FETCH_CHUNK_SIZE):
        validators = await consensus_client.get_validators_by_ids(
            indexes[i : i + settings.VALIDATORS_FETCH_CHUNK_SIZE]
        )
        for beacon_validator in validators['data']:
            result[int(beacon_validator['index'])] = beacon_validator['validator']['pubkey']

    return result
