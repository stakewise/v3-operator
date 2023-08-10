import asyncio
from unittest import mock

import pytest
from eth_typing import BlockNumber

from src.exits.tasks import wait_oracle_signature_update


class TestWaitOracleSignatureUpdate:
    async def test_normal(self, fake_settings):
        update_block = BlockNumber(3)
        with (
            mock.patch('asyncio.sleep'),
            mock.patch('src.exits.tasks.time.time', return_value=100),
            mock.patch(
                'src.exits.tasks._fetch_exit_signature_block', side_effect=[None, 1, 2, 3]
            ) as fetch_mock,
        ):
            await wait_oracle_signature_update(update_block, 'http://oracle', max_time=5)

        assert fetch_mock.call_count == 4

    async def test_timeout(self, fake_settings):
        update_block = BlockNumber(3)
        with (
            mock.patch('asyncio.sleep'),
            mock.patch('src.exits.tasks.time.time', side_effect=[100, 103, 106]),
            mock.patch(
                'src.exits.tasks._fetch_exit_signature_block', return_value=None
            ) as fetch_mock,
            pytest.raises(asyncio.TimeoutError),
        ):
            await wait_oracle_signature_update(update_block, 'http://oracle', max_time=5)

        assert fetch_mock.call_count == 2
