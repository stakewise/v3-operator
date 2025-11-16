from logging import INFO, LogRecord

import pytest

from src.common.logging import TokenPlainFormatter
from src.config.settings import settings


@pytest.mark.usefixtures('fake_settings')
def test_log_filter():
    settings.execution_endpoints = [
        'https://ethereum-hoodi.core.chainstack.com/tokenexample',
        'https://compatible-stylish-lake.ethereum-hoodi.quiknode.pro/tokenexample',
        'https://eth-hoodi.g.alchemy.com/v2/tokenexample',
        'https://node-00.stakewise.io/mainnet-lighthouse',
    ]
    pairs = [
        (
            'https://ethereum-hoodi.core.chainstack.com/tokenexample',
            'https://ethereum-hoodi.core.chainstack.com/<hidden>',
        ),
        (
            'https://ethereum-hoodi.core.chainstack.com/tokenexample/eth/v1/beacon/states/head/validators?id=1723408',
            'https://ethereum-hoodi.core.chainstack.com/<hidden>/eth/v1/beacon/states/head/validators?id=1723408',
        ),
        (
            'https://compatible-stylish-lake.ethereum-hoodi.quiknode.pro/tokenexample',
            'https://compatible-stylish-lake.ethereum-hoodi.quiknode.pro/<hidden>',
        ),
        (
            'https://eth-hoodi.g.alchemy.com/v2/tokenexample',
            'https://eth-hoodi.g.alchemy.com/<hidden>',
        ),
        (
            'https://node-00.stakewise.io/mainnet-lighthouse/eth/v1/beacon/states/head/validators?id=1723408',
            'https://node-00.stakewise.io/mainnet-lighthouse/eth/v1/beacon/states/head/validators?id=1723408',
        ),
    ]
    for str_in, str_out in pairs:
        record = LogRecord(
            msg=str_in,
            name='name',
            level=INFO,
            pathname='example.py',
            lineno=1,
            args=(),
            exc_info=None,
        )
        assert TokenPlainFormatter().format(record) == str_out
