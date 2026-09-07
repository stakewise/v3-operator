import time
from unittest import mock

import pytest
from aioresponses import aioresponses
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount

import src
from src.config.settings import TELEMETRY_INTERVAL, settings
from src.telemetry.tasks import (
    TELEMETRY_ENDPOINT,
    TelemetryTask,
    build_telemetry_message,
)


@pytest.fixture
def test_account() -> LocalAccount:
    # pylint: disable-next=no-value-for-parameter
    return Account.from_key('0x' + '11' * 32)


@pytest.fixture
def telemetry_url() -> str:
    return f'{settings.network_config.STAKEWISE_REST_API_URL}/{TELEMETRY_ENDPOINT}'


@pytest.mark.usefixtures('fake_settings')
class TestTelemetryTask:
    async def test_reports_signed_version(
        self, test_account: LocalAccount, telemetry_url: str
    ) -> None:
        with mock.patch('src.telemetry.tasks.wallet', test_account), aioresponses() as m:
            m.post(telemetry_url, status=200, payload={'success': True})
            await TelemetryTask().process_block(mock.Mock())

            request = list(m.requests.values())[0][0]

        payload = request.kwargs['json']
        assert payload['vault'] == settings.vault
        assert payload['operator_version'] == src.__version__
        assert 'message' not in payload

        message = build_telemetry_message(
            vault=payload['vault'],
            operator_version=payload['operator_version'],
            timestamp=payload['timestamp'],
        )
        assert message == (f'operator_{payload['timestamp']}_{settings.vault}_{src.__version__}')

        signer = Account.recover_message(
            encode_defunct(text=message), signature=payload['signature']
        )
        assert signer == test_account.address

    async def test_signature_is_fresh(self, test_account: LocalAccount, telemetry_url: str) -> None:
        with mock.patch('src.telemetry.tasks.wallet', test_account), aioresponses() as m:
            m.post(telemetry_url, status=200, payload={'success': True})
            await TelemetryTask().process_block(mock.Mock())

            request = list(m.requests.values())[0][0]

        assert abs(request.kwargs['json']['timestamp'] - int(time.time())) < 60

    async def test_throttled_within_interval(
        self, test_account: LocalAccount, telemetry_url: str
    ) -> None:
        task = TelemetryTask()

        with mock.patch('src.telemetry.tasks.wallet', test_account), aioresponses() as m:
            m.post(telemetry_url, status=200, payload={'success': True}, repeat=True)

            await task.process_block(mock.Mock())
            await task.process_block(mock.Mock())
            assert len(list(m.requests.values())[0]) == 1

            # move the last report beyond the interval
            task.last_report_timestamp -= TELEMETRY_INTERVAL + 1
            await task.process_block(mock.Mock())
            assert len(list(m.requests.values())[0]) == 2

    async def test_error_is_not_propagated(
        self, test_account: LocalAccount, telemetry_url: str
    ) -> None:
        task = TelemetryTask()

        with mock.patch('src.telemetry.tasks.wallet', test_account), aioresponses() as m:
            m.post(telemetry_url, status=400, payload={'detail': 'Vault not found.'}, repeat=True)

            await task.process_block(mock.Mock())
            assert len(list(m.requests.values())[0]) == 1

            # failed attempt still backs off for a full interval
            await task.process_block(mock.Mock())
            assert len(list(m.requests.values())[0]) == 1
