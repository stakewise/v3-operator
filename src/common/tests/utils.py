from contextlib import contextmanager
from decimal import Decimal
from typing import Generator
from unittest.mock import AsyncMock, patch

from web3 import Web3
from web3.types import Gwei, Wei


def ether_to_gwei(value: int | float | Decimal) -> Gwei:
    return Gwei(int(value * 10**9))


def parse_wei(value: str | list | dict) -> Wei:
    if isinstance(value, str):
        number, unit = value.split(' ')
        return Web3.to_wei(number, unit)

    if isinstance(value, list):
        return [parse_wei(value) for value in value]

    if isinstance(value, dict):
        return {key: parse_wei(value) for key, value in value.items()}

    raise ValueError(f'Unsupported type for parse_wei: {type(value)}')


@contextmanager
def patch_consensus_client(
    consensus_client: AsyncMock | None = None,
) -> Generator[AsyncMock, None, None]:
    """Patches the consensus client used by `src.validators.consensus`."""
    consensus_client = consensus_client or AsyncMock()
    with patch('src.validators.consensus.default_consensus_client', consensus_client):
        yield consensus_client
