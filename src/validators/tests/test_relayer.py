import logging
from secrets import token_hex
from time import time
from typing import AsyncIterator

import jwt
import pytest
from aiohttp import ClientResponseError, web
from aiohttp.test_utils import TestServer
from sw_utils.tests import faker
from web3.types import Gwei

from src.config.settings import settings
from src.validators.relayer import RelayerClient

pytestmark = pytest.mark.asyncio(loop_scope='session')


class RelayerStub:
    def __init__(self) -> None:
        self.auth_headers: list[str | None] = []
        self.status = 200

    async def handle(self, request: web.Request) -> web.Response:
        self.auth_headers.append(request.headers.get('Authorization'))
        if self.status != 200:
            return web.Response(status=self.status)
        return web.json_response({'validators': [], 'validators_manager_signature': '0x'})


@pytest.fixture
async def relayer_stub(fake_settings: None) -> AsyncIterator[RelayerStub]:
    stub = RelayerStub()
    app = web.Application()
    for endpoint in ('register', 'fund', 'withdraw', 'consolidate'):
        app.router.add_post(f'/{endpoint}', stub.handle)

    server = TestServer(app)
    await server.start_server()
    settings.relayer_endpoint = str(server.make_url('/'))
    settings.relayer_jwt_secret = None
    yield stub
    await server.close()


async def test_no_auth_header_without_secret(relayer_stub: RelayerStub) -> None:
    await _call_all_endpoints(RelayerClient())

    assert relayer_stub.auth_headers == [None] * 4


async def test_auth_header_with_secret(relayer_stub: RelayerStub) -> None:
    secret_hex = token_hex(32)
    settings.relayer_jwt_secret = secret_hex

    await _call_all_endpoints(RelayerClient())

    assert len(relayer_stub.auth_headers) == 4
    for header in relayer_stub.auth_headers:
        assert header is not None
        scheme, token = header.split(' ')
        assert scheme == 'Bearer'
        claims = jwt.decode(token, bytes.fromhex(secret_hex), algorithms=['HS256'])
        assert abs(time() - claims['iat']) <= 1


async def test_new_token_per_request(relayer_stub: RelayerStub) -> None:
    settings.relayer_jwt_secret = token_hex(32)
    client = RelayerClient()
    public_key = faker.validator_public_key()

    await client.fund_validators([(public_key, Gwei(1_000_000_000))])
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr('src.validators.relayer.time', lambda: time() + 10)
        await client.fund_validators([(public_key, Gwei(1_000_000_000))])

    first, second = relayer_stub.auth_headers
    assert first != second


async def test_unauthorized_logged(
    relayer_stub: RelayerStub, caplog: pytest.LogCaptureFixture
) -> None:
    relayer_stub.status = 401
    public_key = faker.validator_public_key()

    with caplog.at_level(logging.ERROR, logger='src.validators.relayer'), pytest.raises(
        ClientResponseError
    ):
        await RelayerClient().fund_validators([(public_key, Gwei(1_000_000_000))])

    assert 'Check that RELAYER_JWT_SECRET matches' in caplog.text


async def _call_all_endpoints(client: RelayerClient) -> None:
    public_key = faker.validator_public_key()
    await client._register_validators(settings.vault, 0, [Gwei(32_000_000_000)])
    await client.fund_validators([(public_key, Gwei(1_000_000_000))])
    await client.withdraw_validators({public_key: Gwei(1_000_000_000)})
    await client.consolidate_validators(settings.vault, [(public_key, public_key)])
