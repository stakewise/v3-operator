import asyncio
from unittest import mock

import pytest

from src.exits.tasks import wait_oracle_signature_update


class TestWaitOracleSignatureUpdate:
    async def test_normal(self, fake_settings):
        updated_indexes = [1, 2]
        with (
            mock.patch('asyncio.sleep'),
            mock.patch('src.exits.tasks.time.time', return_value=100),
            mock.patch(
                'src.exits.tasks._fetch_outdated_indexes', side_effect=[[1, 2, 3], [3]]
            ) as fetch_mock,
        ):
            await wait_oracle_signature_update(updated_indexes, 'http://oracle', max_time=5)

        assert fetch_mock.call_count == 2

    async def test_timeout(self, fake_settings):
        updated_indexes = [1, 2]
        with (
            mock.patch('asyncio.sleep'),
            mock.patch('src.exits.tasks.time.time', side_effect=[100, 103, 106]),
            mock.patch(
                'src.exits.tasks._fetch_outdated_indexes', return_value=[1, 3]
            ) as fetch_mock,
            pytest.raises(asyncio.TimeoutError),
        ):
            await wait_oracle_signature_update(updated_indexes, 'http://oracle', max_time=5)

        assert fetch_mock.call_count == 2
