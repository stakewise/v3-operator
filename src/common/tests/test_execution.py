from unittest import mock

import pytest

from src.common.execution import _get_config_ipfs_hash_since_checkpoint
from src.config.settings import settings

GET_EVENT_FUNC = 'src.common.execution.keeper_contract.get_config_updated_event'


@pytest.mark.usefixtures('fake_settings')
class TestGetConfigIpfsHashSinceCheckpoint:
    async def test_event_after_checkpoint(self):
        event = {'args': {'configIpfsHash': 'QmNewHash'}}
        with (
            mock.patch.object(
                settings.network_config.CHECKPOINTS, 'CONFIG_UPDATE_CHECKPOINT_BLOCK', 100
            ),
            mock.patch.object(
                settings.network_config.CHECKPOINTS,
                'CONFIG_UPDATE_LAST_EVENT_IPFS_HASH',
                'QmOldHash',
            ),
            mock.patch(GET_EVENT_FUNC, return_value=event) as get_event_mock,
        ):
            ipfs_hash = await _get_config_ipfs_hash_since_checkpoint(to_block=150)

        assert ipfs_hash == 'QmNewHash'
        get_event_mock.assert_called_once_with(from_block=101, to_block=150)

    async def test_no_event_after_checkpoint(self):
        with (
            mock.patch.object(
                settings.network_config.CHECKPOINTS, 'CONFIG_UPDATE_CHECKPOINT_BLOCK', 100
            ),
            mock.patch.object(
                settings.network_config.CHECKPOINTS,
                'CONFIG_UPDATE_LAST_EVENT_IPFS_HASH',
                'QmOldHash',
            ),
            mock.patch(GET_EVENT_FUNC, return_value=None) as get_event_mock,
        ):
            ipfs_hash = await _get_config_ipfs_hash_since_checkpoint(to_block=150)

        assert ipfs_hash == 'QmOldHash'
        get_event_mock.assert_called_once_with(from_block=101, to_block=150)

    async def test_head_below_checkpoint(self):
        """No event logs are read when the node is behind the checkpoint."""
        with (
            mock.patch.object(
                settings.network_config.CHECKPOINTS, 'CONFIG_UPDATE_CHECKPOINT_BLOCK', 100
            ),
            mock.patch.object(
                settings.network_config.CHECKPOINTS,
                'CONFIG_UPDATE_LAST_EVENT_IPFS_HASH',
                'QmOldHash',
            ),
            mock.patch(GET_EVENT_FUNC, return_value=None) as get_event_mock,
        ):
            ipfs_hash = await _get_config_ipfs_hash_since_checkpoint(to_block=50)

        assert ipfs_hash == 'QmOldHash'
        get_event_mock.assert_not_called()

    async def test_no_fallback_hash(self):
        with (
            mock.patch.object(
                settings.network_config.CHECKPOINTS, 'CONFIG_UPDATE_CHECKPOINT_BLOCK', 100
            ),
            mock.patch.object(
                settings.network_config.CHECKPOINTS, 'CONFIG_UPDATE_LAST_EVENT_IPFS_HASH', ''
            ),
            mock.patch(GET_EVENT_FUNC, return_value=None),
            pytest.raises(RuntimeError, match="Can't find oracle config"),
        ):
            await _get_config_ipfs_hash_since_checkpoint(to_block=150)
