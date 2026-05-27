import pytest

from src.common.typings import Singleton
from src.redemptions.fetch_positions import ProcessedSharesCache


@pytest.fixture(autouse=True)
def reset_cache():
    Singleton._instances.pop(ProcessedSharesCache, None)
    yield
    Singleton._instances.pop(ProcessedSharesCache, None)
