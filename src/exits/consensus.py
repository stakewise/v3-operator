from sw_utils.decorators import backoff_aiohttp_errors
from web3.types import HexStr

from src.common.clients import consensus_client
from src.config.settings import DEFAULT_RETRY_TIME, VALIDATORS_FETCH_CHUNK_SIZE


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def get_validator_public_keys(validator_indexes: list[int]) -> dict[int, HexStr]:
    """Fetches validators public keys."""
    indexes = [str(index) for index in validator_indexes]
    result = {}
    for i in range(0, len(indexes), VALIDATORS_FETCH_CHUNK_SIZE):
        validators = await consensus_client.get_validators_by_ids(
            indexes[i: i + VALIDATORS_FETCH_CHUNK_SIZE]
        )
        for beacon_validator in validators['data']:
            result[int(beacon_validator['index'])] = beacon_validator['validator']['pubkey']

    return result
