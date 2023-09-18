import pytest
from sw_utils.typings import ConsensusFork


@pytest.fixture
def fork() -> ConsensusFork:
    return ConsensusFork(
        version=bytes.fromhex('00000001'),
        epoch=1,
    )
