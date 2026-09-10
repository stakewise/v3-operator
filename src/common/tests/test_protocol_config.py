from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from eth_typing import BlockNumber
from web3.types import EventData

from src.common.app_state import AppState, OraclesCache
from src.common.protocol_config import (
    _get_config_updated_event_since_checkpoint,
    update_oracles_cache,
)
from src.config.settings import settings


@pytest.mark.usefixtures('fake_settings')
class TestGetConfigUpdatedEventSinceCheckpoint:
    async def test_returns_recent_event(self):
        """An event after the checkpoint is returned without the fallback query."""
        expected_event = _config_event('hash1')

        with patch(
            'src.common.protocol_config.keeper_contract.get_config_updated_event',
            new_callable=AsyncMock,
            return_value=expected_event,
        ) as mock_event, _mock_checkpoints():
            result = await _get_config_updated_event_since_checkpoint(to_block=BlockNumber(100000))

        assert result is expected_event
        mock_event.assert_awaited_once_with(
            from_block=BlockNumber(90001), to_block=BlockNumber(100000)
        )

    async def test_falls_back_to_last_event_block(self):
        """With no event since the checkpoint, the last known event block is queried."""
        last_event = _config_event('last')

        with patch(
            'src.common.protocol_config.keeper_contract.get_config_updated_event',
            new_callable=AsyncMock,
            side_effect=[None, last_event],
        ) as mock_event, _mock_checkpoints():
            result = await _get_config_updated_event_since_checkpoint(to_block=BlockNumber(100000))

        assert result is last_event
        assert mock_event.await_args_list == [
            call(from_block=BlockNumber(90001), to_block=BlockNumber(100000)),
            call(from_block=BlockNumber(80000), to_block=BlockNumber(80000)),
        ]

    async def test_node_behind_checkpoint_skips_scan(self):
        """Node lagging behind the checkpoint queries the last event block only."""
        last_event = _config_event('last')

        with patch(
            'src.common.protocol_config.keeper_contract.get_config_updated_event',
            new_callable=AsyncMock,
            return_value=last_event,
        ) as mock_event, _mock_checkpoints():
            result = await _get_config_updated_event_since_checkpoint(to_block=BlockNumber(85000))

        assert result is last_event
        mock_event.assert_awaited_once_with(
            from_block=BlockNumber(80000), to_block=BlockNumber(80000)
        )


@pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
class TestUpdateOraclesCache:
    def setup_method(self) -> None:
        # AppState is a process-wide singleton; reset the cache between tests.
        AppState().oracles_cache = None

    async def test_cold_cache_fetches_and_populates(self):
        with _mock_block_number(BlockNumber(100)), patch(
            'src.common.protocol_config._get_config_updated_event_since_checkpoint',
            new_callable=AsyncMock,
            return_value=_config_event('hash1'),
        ) as mock_event, patch(
            'src.common.protocol_config.ipfs_fetch_client.fetch_json',
            new_callable=AsyncMock,
            return_value={'k': 'v1'},
        ) as mock_fetch, self._mock_thresholds():
            await update_oracles_cache()

        # Cold path: delegates to the checkpoint-aware lookup.
        mock_event.assert_awaited_once_with(to_block=BlockNumber(100))
        mock_fetch.assert_awaited_once_with('hash1')

        oracles_cache = AppState().oracles_cache
        assert oracles_cache.checkpoint_block == BlockNumber(100)
        assert oracles_cache.config == {'k': 'v1'}
        assert oracles_cache.rewards_threshold == 3
        assert oracles_cache.validators_threshold == 5

    async def test_cold_cache_no_event_raises(self):
        with _mock_block_number(BlockNumber(100)), patch(
            'src.common.protocol_config._get_config_updated_event_since_checkpoint',
            new_callable=AsyncMock,
            return_value=None,
        ), pytest.raises(ValueError, match='Failed to fetch IPFS hash of oracles config'):
            await update_oracles_cache()

    async def test_warm_cache_no_new_event_reuses_config(self):
        AppState().oracles_cache = OraclesCache(
            checkpoint_block=BlockNumber(100),
            config={'k': 'cached'},
            validators_threshold=5,
            rewards_threshold=3,
        )

        with _mock_block_number(BlockNumber(105)), patch(
            'src.common.protocol_config.keeper_contract.get_config_updated_event',
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_event, patch(
            'src.common.protocol_config.ipfs_fetch_client.fetch_json', new_callable=AsyncMock
        ) as mock_fetch, self._mock_thresholds():
            await update_oracles_cache()

        # Warm path: incremental scan only, no IPFS fetch when nothing changed.
        mock_event.assert_awaited_once_with(from_block=BlockNumber(101), to_block=BlockNumber(105))
        mock_fetch.assert_not_awaited()

        oracles_cache = AppState().oracles_cache
        assert oracles_cache.checkpoint_block == BlockNumber(105)
        assert oracles_cache.config == {'k': 'cached'}

    async def test_warm_cache_new_event_refetches(self):
        AppState().oracles_cache = OraclesCache(
            checkpoint_block=BlockNumber(100),
            config={'k': 'old'},
            validators_threshold=5,
            rewards_threshold=3,
        )

        with _mock_block_number(BlockNumber(110)), patch(
            'src.common.protocol_config.keeper_contract.get_config_updated_event',
            new_callable=AsyncMock,
            return_value=_config_event('hash2'),
        ) as mock_event, patch(
            'src.common.protocol_config.ipfs_fetch_client.fetch_json',
            new_callable=AsyncMock,
            return_value={'k': 'new'},
        ) as mock_fetch, self._mock_thresholds():
            await update_oracles_cache()

        mock_event.assert_awaited_once_with(from_block=BlockNumber(101), to_block=BlockNumber(110))
        mock_fetch.assert_awaited_once_with('hash2')

        oracles_cache = AppState().oracles_cache
        assert oracles_cache.checkpoint_block == BlockNumber(110)
        assert oracles_cache.config == {'k': 'new'}

    async def test_warm_cache_no_new_block_skips_scan(self):
        AppState().oracles_cache = OraclesCache(
            checkpoint_block=BlockNumber(100),
            config={'k': 'cached'},
            validators_threshold=5,
            rewards_threshold=3,
        )

        with _mock_block_number(BlockNumber(100)), patch(
            'src.common.protocol_config.keeper_contract.get_config_updated_event',
            new_callable=AsyncMock,
        ) as mock_event, patch(
            'src.common.protocol_config.ipfs_fetch_client.fetch_json', new_callable=AsyncMock
        ) as mock_fetch, self._mock_thresholds():
            await update_oracles_cache()

        mock_event.assert_not_awaited()
        mock_fetch.assert_not_awaited()

        oracles_cache = AppState().oracles_cache
        assert oracles_cache.checkpoint_block == BlockNumber(100)
        assert oracles_cache.config == {'k': 'cached'}

    @staticmethod
    def _mock_thresholds():
        return patch(
            'src.common.protocol_config.multicall_contract.aggregate',
            new_callable=AsyncMock,
            return_value=(None, [(3).to_bytes(32, 'big'), (5).to_bytes(32, 'big')]),
        )


def _config_event(ipfs_hash: str) -> EventData:
    return EventData(
        event='ConfigUpdated',
        args={'configIpfsHash': ipfs_hash},
        blockNumber=BlockNumber(0),
    )


def _mock_block_number(block_number: BlockNumber):
    client = MagicMock()
    client.eth.get_block_number = AsyncMock(return_value=block_number)
    return patch('src.common.protocol_config.execution_client', client)


def _mock_checkpoints():
    """Pins the checkpoint / last event blocks of the network config."""
    return patch.multiple(
        settings.network_config.CHECKPOINTS,
        CONFIG_UPDATE_CHECKPOINT_BLOCK=BlockNumber(90000),
        CONFIG_UPDATE_LAST_EVENT_BLOCK=BlockNumber(80000),
    )
