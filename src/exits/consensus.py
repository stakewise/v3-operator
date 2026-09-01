import logging

from web3.types import HexStr

from src.common.clients import consensus_client
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def get_validator_public_keys(validator_indexes: list[int]) -> dict[int, HexStr]:
    """Fetches validators public keys."""
    indexes = [str(index) for index in validator_indexes]
    result: dict[int, HexStr] = {}
    for i in range(0, len(indexes), settings.validators_fetch_chunk_size):
        validators = await consensus_client.get_validators_by_ids(
            indexes[i : i + settings.validators_fetch_chunk_size],
            state_id='finalized',
        )
        for beacon_validator in validators['data']:
            index = int(beacon_validator['index'])
            if index not in validator_indexes:
                logger.warning(
                    'Consensus client returned validator index %d that was not requested; '
                    'skipping it',
                    index,
                )
                continue
            result[index] = beacon_validator['validator']['pubkey']

    return result
