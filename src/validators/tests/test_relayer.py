import logging
from secrets import token_hex
from time import time
from typing import Iterator
from unittest import mock

import jwt
import pytest
from aiohttp import ClientResponseError
from aioresponses import aioresponses
from sw_utils.tests import faker
from web3.types import Gwei

from src.config.settings import settings
from src.validators.relayer import RelayerClient

RELAYER_ENDPOINT = 'http://relayer'
RELAYER_RESPONSE = {'validators': [], 'validators_manager_signature': '0x'}


@pytest.fixture
def relayer_mock(fake_settings: None) -> Iterator[aioresponses]:
    settings.relayer_endpoint = RELAYER_ENDPOINT
    settings.relayer_jwt_secret = None
    with aioresponses() as m:
        for endpoint in ('register', 'fund', 'withdraw', 'consolidate'):
            m.post(f'{RELAYER_ENDPOINT}/{endpoint}', payload=RELAYER_RESPONSE, repeat=True)
        yield m


async def test_no_auth_header_without_secret(relayer_mock: aioresponses) -> None:
    await _call_all_endpoints(RelayerClient())

    assert _get_auth_headers(relayer_mock) == [None] * 4


async def test_auth_header_with_secret(relayer_mock: aioresponses) -> None:
    secret_hex = token_hex(32)
    settings.relayer_jwt_secret = secret_hex

    await _call_all_endpoints(RelayerClient())

    auth_headers = _get_auth_headers(relayer_mock)
    assert len(auth_headers) == 4
    for header in auth_headers:
        assert header is not None
        scheme, token = header.split(' ')
        assert scheme == 'Bearer'
        claims = jwt.decode(token, bytes.fromhex(secret_hex), algorithms=['HS256'])
        assert abs(time() - claims['iat']) <= 1


async def test_new_token_per_request(relayer_mock: aioresponses) -> None:
    settings.relayer_jwt_secret = token_hex(32)
    client = RelayerClient()
    public_key = faker.validator_public_key()

    await client.fund_validators([(public_key, Gwei(1_000_000_000))])
    with mock.patch('src.validators.relayer.time', return_value=time() + 10):
        await client.fund_validators([(public_key, Gwei(1_000_000_000))])

    first, second = _get_auth_headers(relayer_mock)
    assert first != second


async def test_unauthorized_logged(caplog: pytest.LogCaptureFixture, fake_settings: None) -> None:
    settings.relayer_endpoint = RELAYER_ENDPOINT
    public_key = faker.validator_public_key()

    with aioresponses() as m, caplog.at_level(
        logging.ERROR, logger='src.validators.relayer'
    ), pytest.raises(ClientResponseError):
        m.post(f'{RELAYER_ENDPOINT}/fund', status=401)
        await RelayerClient().fund_validators([(public_key, Gwei(1_000_000_000))])

    assert 'Check that RELAYER_JWT_SECRET matches' in caplog.text


async def _call_all_endpoints(client: RelayerClient) -> None:
    public_key = faker.validator_public_key()
    await client._register_validators(settings.vault, 0, [Gwei(32_000_000_000)])
    await client.fund_validators([(public_key, Gwei(1_000_000_000))])
    await client.withdraw_validators({public_key: Gwei(1_000_000_000)})
    await client.consolidate_validators(settings.vault, [(public_key, public_key)])


def _get_auth_headers(m: aioresponses) -> list[str | None]:
    return [
        call.kwargs['headers'].get('Authorization')
        for calls in m.requests.values()
        for call in calls
    ]
