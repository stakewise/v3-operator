from logging import INFO, LogRecord
from unittest import mock

import pytest

from src.common.logging import TokenPlainFormatter
from src.config.settings import settings


@pytest.mark.usefixtures('fake_settings')
@pytest.mark.parametrize(
    'raw_endpoint,hidden_endpoint',
    [
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
        (
            'http://localhost:8545/eth/v1/beacon/states/head/validators?id=1723408',
            'http://localhost:8545/eth/v1/beacon/states/head/validators?id=1723408',
        ),
        (
            'https://rpc.public-node.io/eth/v1/beacon/states/head/validators?id=1723408',
            'https://rpc.public-node.io/eth/v1/beacon/states/head/validators?id=1723408',
        ),
    ],
)
def test_token_formatter(raw_endpoint, hidden_endpoint):
    execution_endpoints = [
        'https://ethereum-hoodi.core.chainstack.com/tokenexample',
        'https://compatible-stylish-lake.ethereum-hoodi.quiknode.pro/tokenexample',
        'https://eth-hoodi.g.alchemy.com/v2/tokenexample',
        'https://node-00.stakewise.io/mainnet-lighthouse',
        'http://localhost:8545',
        'https://rpc.public-node.io',
    ]
    str_in = f'Retrying {raw_endpoint}, attempt 2...'
    str_out = f'Retrying {hidden_endpoint}, attempt 2...'

    record = LogRecord(
        msg=str_in,
        name='name',
        level=INFO,
        pathname='example.py',
        lineno=1,
        args=(),
        exc_info=None,
    )
    with mock.patch.object(settings, 'execution_endpoints', execution_endpoints):
        assert TokenPlainFormatter().format(record) == str_out


@pytest.mark.usefixtures('fake_settings')
@pytest.mark.parametrize(
    'raw_endpoint,hidden_endpoint',
    [
        (
            'http://localhost:8545/eth/v1/beacon/states/head/validators?id=1723408',
            'http://localhost:8545/eth/v1/beacon/states/head/validators?id=1723408',
        ),
        (
            'https://rpc.public-node.io/eth/v1/beacon/states/head/validators?id=1723408',
            'https://rpc.public-node.io/eth/v1/beacon/states/head/validators?id=1723408',
        ),
    ],
)
def test_token_formatter_with_trailing_slash(raw_endpoint, hidden_endpoint):
    execution_endpoints = [
        'http://localhost:8545/',
        'https://rpc.public-node.io/',
    ]
    str_in = f'Retrying {raw_endpoint}, attempt 2...'
    str_out = f'Retrying {hidden_endpoint}, attempt 2...'

    record = LogRecord(
        msg=str_in,
        name='name',
        level=INFO,
        pathname='example.py',
        lineno=1,
        args=(),
        exc_info=None,
    )
    with mock.patch.object(settings, 'execution_endpoints', execution_endpoints):
        assert TokenPlainFormatter().format(record) == str_out
