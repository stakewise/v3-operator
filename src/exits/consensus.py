import logging

from web3.types import HexStr

from src.validators.consensus import iter_validators_by_ids

logger = logging.getLogger(__name__)


async def get_validator_public_keys(validator_indexes: list[int]) -> dict[int, HexStr]:
    """Fetches validators public keys."""
    indexes = [str(index) for index in validator_indexes]
    result: dict[int, HexStr] = {}
    async for validator in iter_validators_by_ids(indexes, state_id='finalized'):
        if validator.index not in validator_indexes:
            logger.warning(
                'Consensus client returned validator index %d that was not requested; '
                'skipping it',
                validator.index,
            )
            continue
        result[validator.index] = validator.public_key

    return result
