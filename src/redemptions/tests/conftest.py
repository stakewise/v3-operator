import pytest

from src.common.typings import Singleton
from src.redemptions.fetch_positions import IpfsPositionsCache, ProcessedSharesCache


@pytest.fixture(autouse=True)
def reset_cache():
    Singleton._instances.pop(ProcessedSharesCache, None)
    Singleton._instances.pop(IpfsPositionsCache, None)
    yield
    Singleton._instances.pop(ProcessedSharesCache, None)
    Singleton._instances.pop(IpfsPositionsCache, None)
