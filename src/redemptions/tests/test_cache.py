from unittest.mock import AsyncMock, MagicMock, patch

from eth_typing import BlockNumber
from web3 import Web3
from web3.types import Wei

from src.config.settings import settings
from src.redemptions.fetch_positions import (
    ProcessedSharesCache,
    update_processed_shares_cache,
)
from src.redemptions.tests.factories import make_position


class TestProcessedSharesCacheIsValidOn:
    async def test_nonce_mismatch_returns_false(self):
        cache = ProcessedSharesCache()
        cache.nonce = 1
        assert await cache.is_valid_on(nonce=2, block_number=BlockNumber(100)) is False

    async def test_same_checkpoint_block_returns_true(self):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = BlockNumber(100)
        assert await cache.is_valid_on(nonce=5, block_number=BlockNumber(100)) is True

    async def test_checkpoint_block_in_future_returns_false(self):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = BlockNumber(200)
        assert await cache.is_valid_on(nonce=5, block_number=BlockNumber(100)) is False

    async def test_no_events_returns_true(self):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = BlockNumber(90)
        with patch(
            'src.redemptions.fetch_positions.os_token_redeemer_contract'
            '.get_os_token_positions_redeemed_events',
            new=AsyncMock(return_value=[]),
        ):
            result = await cache.is_valid_on(nonce=5, block_number=BlockNumber(100))
        assert result is True

    async def test_has_events_returns_false(self):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = BlockNumber(90)
        with patch(
            'src.redemptions.fetch_positions.os_token_redeemer_contract'
            '.get_os_token_positions_redeemed_events',
            new=AsyncMock(return_value=[object()]),
        ):
            result = await cache.is_valid_on(nonce=5, block_number=BlockNumber(100))
        assert result is False

    async def test_no_checkpoint_uses_genesis_block(self, fake_settings):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = None
        mock_events = AsyncMock(return_value=[])
        with patch(
            'src.redemptions.fetch_positions.os_token_redeemer_contract'
            '.get_os_token_positions_redeemed_events',
            new=mock_events,
        ):
            result = await cache.is_valid_on(nonce=5, block_number=BlockNumber(100))
        assert result is True
        call_kwargs = mock_events.call_args.kwargs
        assert call_kwargs['from_block'] == settings.network_config.OS_TOKEN_REDEEMER_GENESIS_BLOCK

    async def test_checkpoint_set_uses_next_block(self):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = BlockNumber(50)
        mock_events = AsyncMock(return_value=[])
        with patch(
            'src.redemptions.fetch_positions.os_token_redeemer_contract'
            '.get_os_token_positions_redeemed_events',
            new=mock_events,
        ):
            await cache.is_valid_on(nonce=5, block_number=BlockNumber(100))
        call_kwargs = mock_events.call_args.kwargs
        assert call_kwargs['from_block'] == BlockNumber(51)
        assert call_kwargs['to_block'] == BlockNumber(100)


MODULE = 'src.redemptions.fetch_positions'


class TestUpdateProcessedSharesCache:
    async def test_already_up_to_date(self):
        cache = ProcessedSharesCache()
        cache.checkpoint_block = BlockNumber(100)

        mock_get_block = self._mock_finalized_block(100)
        mock_client = MagicMock()
        mock_client.eth.get_block = mock_get_block
        with patch(f'{MODULE}.execution_client', new=mock_client):
            await update_processed_shares_cache()

        # nonce was never fetched
        assert cache.checkpoint_block == BlockNumber(100)

    async def test_zero_nonce_sets_checkpoint(self):
        cache = ProcessedSharesCache()

        mock_get_block = self._mock_finalized_block(100)
        mock_client = MagicMock()
        mock_client.eth.get_block = mock_get_block
        with patch(f'{MODULE}.execution_client', new=mock_client), patch(
            f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=0)
        ):
            await update_processed_shares_cache()

        assert cache.nonce == 0
        assert cache.checkpoint_block == BlockNumber(100)
        assert cache.data == {}

    async def test_valid_cache_only_updates_checkpoint(self):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = BlockNumber(90)
        cache.data = {'0xabc': Wei(123)}

        mock_get_block = self._mock_finalized_block(100)
        mock_client = MagicMock()
        mock_client.eth.get_block = mock_get_block
        with patch(f'{MODULE}.execution_client', new=mock_client), patch(
            f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=5)
        ), patch(
            f'{MODULE}.os_token_redeemer_contract.get_os_token_positions_redeemed_events',
            new=AsyncMock(return_value=[]),
        ):
            await update_processed_shares_cache()

        assert cache.checkpoint_block == BlockNumber(100)
        assert cache.data == {'0xabc': Wei(123)}

    async def test_invalid_cache_rebuilds_data(self):
        cache = ProcessedSharesCache()
        cache.nonce = 4
        cache.checkpoint_block = BlockNumber(90)

        pos = make_position(leaf_shares=1000)
        processed = Wei(500)

        async def _iter_shares(*args, **kwargs):
            yield processed

        mock_get_block = self._mock_finalized_block(100)
        mock_client = MagicMock()
        mock_client.eth.get_block = mock_get_block
        with patch(f'{MODULE}.execution_client', new=mock_client), patch(
            f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=5)
        ), patch(
            f'{MODULE}.os_token_redeemer_contract.get_os_token_positions_redeemed_events',
            new=AsyncMock(return_value=[object()]),
        ), patch(
            'src.redemptions.fetch_positions.fetch_positions_from_ipfs',
            new=AsyncMock(return_value=[pos]),
        ), patch(
            'src.redemptions.fetch_positions.iter_processed_shares',
            new=lambda *a, **kw: _iter_shares(),
        ):
            await update_processed_shares_cache()

        assert cache.nonce == 5
        assert cache.checkpoint_block == BlockNumber(100)
        expected_key = Web3.to_hex(pos.leaf_hash(4))
        assert cache.data == {expected_key: processed}

    def _mock_finalized_block(self, block_number: int) -> AsyncMock:
        block = MagicMock()
        block.__getitem__ = lambda self, key: block_number if key == 'number' else None
        return AsyncMock(return_value=block)
