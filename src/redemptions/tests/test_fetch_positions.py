from unittest import mock
from unittest.mock import AsyncMock, patch

import pytest
from eth_typing import BlockNumber
from web3 import Web3
from web3.types import Wei

from src.config.settings import OS_TOKEN_REDEEMER_CHUNK_SIZE, settings
from src.redemptions.fetch_positions import (
    ZERO_MERKLE_ROOT,
    IpfsPositionsCache,
    ProcessedSharesCache,
    cached_fetch_positions_from_ipfs,
    cached_iter_processed_shares,
    fetch_positions_from_ipfs,
    iter_processed_shares,
    os_token_redeemer_contract,
    update_positions_cache,
    update_processed_shares_cache,
)
from src.redemptions.tests.factories import create_redeemable_positions, make_position

MODULE = 'src.redemptions.fetch_positions'
BLOCK = BlockNumber(100)
NONCE = 5


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
            f'{MODULE}.os_token_redeemer_contract.get_os_token_positions_redeemed_events',
            new=AsyncMock(return_value=[]),
        ):
            result = await cache.is_valid_on(nonce=5, block_number=BlockNumber(100))
        assert result is True

    async def test_has_events_returns_false(self):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = BlockNumber(90)
        with patch(
            f'{MODULE}.os_token_redeemer_contract.get_os_token_positions_redeemed_events',
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
            f'{MODULE}.os_token_redeemer_contract.get_os_token_positions_redeemed_events',
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
            f'{MODULE}.os_token_redeemer_contract.get_os_token_positions_redeemed_events',
            new=mock_events,
        ):
            await cache.is_valid_on(nonce=5, block_number=BlockNumber(100))
        call_kwargs = mock_events.call_args.kwargs
        assert call_kwargs['from_block'] == BlockNumber(51)
        assert call_kwargs['to_block'] == BlockNumber(100)


class TestUpdateProcessedSharesCache:
    async def test_already_up_to_date(self):
        cache = ProcessedSharesCache()
        cache.checkpoint_block = BlockNumber(100)

        await update_processed_shares_cache(BlockNumber(100))

        assert cache.checkpoint_block == BlockNumber(100)

    async def test_zero_nonce_sets_checkpoint(self):
        cache = ProcessedSharesCache()

        with patch(f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=0)):
            await update_processed_shares_cache(BlockNumber(100))

        assert cache.nonce == 0
        assert cache.checkpoint_block == BlockNumber(100)
        assert cache.data == {}

    async def test_valid_cache_only_updates_checkpoint(self):
        cache = ProcessedSharesCache()
        cache.nonce = 5
        cache.checkpoint_block = BlockNumber(90)
        cache.data = {'0xabc': Wei(123)}

        with patch(
            f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=5)
        ), patch(
            f'{MODULE}.os_token_redeemer_contract.get_os_token_positions_redeemed_events',
            new=AsyncMock(return_value=[]),
        ):
            await update_processed_shares_cache(BlockNumber(100))

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

        with patch(
            f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=5)
        ), patch(
            f'{MODULE}.os_token_redeemer_contract.get_os_token_positions_redeemed_events',
            new=AsyncMock(return_value=[object()]),
        ), patch(
            f'{MODULE}.fetch_positions_from_ipfs',
            new=AsyncMock(return_value=[pos]),
        ), patch(
            f'{MODULE}.iter_processed_shares',
            new=lambda *a, **kw: _iter_shares(),
        ):
            await update_processed_shares_cache(BlockNumber(100))

        assert cache.nonce == 5
        assert cache.checkpoint_block == BlockNumber(100)
        expected_key = Web3.to_hex(pos.leaf_hash(4))
        assert cache.data == {expected_key: processed}


class TestIpfsPositionsCacheIsValidFor:
    def test_nonce_mismatch_returns_false(self):
        cache = IpfsPositionsCache()
        cache.nonce = 1
        assert cache.is_valid_for(nonce=2) is False

    def test_nonce_match_returns_true(self):
        cache = IpfsPositionsCache()
        cache.nonce = NONCE
        assert cache.is_valid_for(nonce=NONCE) is True

    def test_no_cached_nonce_returns_false(self):
        cache = IpfsPositionsCache()
        assert cache.is_valid_for(nonce=NONCE) is False


class TestUpdatePositionsCache:
    async def test_already_up_to_date(self):
        cache = IpfsPositionsCache()
        cache.checkpoint_block = BlockNumber(100)

        await update_positions_cache(BlockNumber(100))

        assert cache.checkpoint_block == BlockNumber(100)

    async def test_zero_nonce_clears_data(self):
        cache = IpfsPositionsCache()

        with patch(f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=0)):
            await update_positions_cache(BlockNumber(100))

        assert cache.nonce == 0
        assert cache.data == []
        assert cache.checkpoint_block == BlockNumber(100)

    async def test_valid_cache_only_updates_checkpoint(self):
        cache = IpfsPositionsCache()
        cache.nonce = NONCE
        cache.checkpoint_block = BlockNumber(90)
        cached = [make_position()]
        cache.data = cached

        with patch(f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=NONCE)):
            await update_positions_cache(BlockNumber(100))

        assert cache.checkpoint_block == BlockNumber(100)
        assert cache.data is cached

    async def test_invalid_cache_refetches_ipfs(self):
        cache = IpfsPositionsCache()
        cache.nonce = NONCE - 1
        cache.checkpoint_block = BlockNumber(90)

        new_positions = [make_position(leaf_shares=999)]

        with patch(
            f'{MODULE}.os_token_redeemer_contract.nonce', new=AsyncMock(return_value=NONCE)
        ), patch(
            f'{MODULE}.fetch_positions_from_ipfs',
            new=AsyncMock(return_value=new_positions),
        ):
            await update_positions_cache(BlockNumber(100))

        assert cache.nonce == NONCE
        assert cache.data == new_positions
        assert cache.checkpoint_block == BlockNumber(100)


class TestFetchPositionsFromIpfs:
    async def test_empty_ipfs_hash_returns_empty(self):
        redeemable = create_redeemable_positions(ipfs_hash='')
        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=AsyncMock(return_value=redeemable),
        ):
            result = await fetch_positions_from_ipfs(block_number=BLOCK)
        assert result == []

    async def test_zero_merkle_root_returns_empty(self):
        redeemable = create_redeemable_positions(merkle_root=ZERO_MERKLE_ROOT)
        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=AsyncMock(return_value=redeemable),
        ):
            result = await fetch_positions_from_ipfs(block_number=BLOCK)
        assert result == []

    async def test_always_fetches_ipfs_regardless_of_cache(self):
        cache = IpfsPositionsCache()
        cache.nonce = NONCE
        cache.checkpoint_block = BLOCK
        cache.data = [make_position()]

        mock_ipfs = AsyncMock(return_value=[make_position(leaf_shares=777).as_dict()])
        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=AsyncMock(return_value=create_redeemable_positions()),
        ), patch(f'{MODULE}.ipfs_fetch_client.fetch_json', new=mock_ipfs):
            result = await fetch_positions_from_ipfs(block_number=BLOCK)

        mock_ipfs.assert_called_once()
        assert result[0].leaf_shares == Wei(777)

    async def test_multiple_positions_parsed(self):
        positions = [make_position(leaf_shares=i * 100, processed_shares=0) for i in range(1, 4)]
        redeemable = create_redeemable_positions()

        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=AsyncMock(return_value=redeemable),
        ), patch(
            f'{MODULE}.ipfs_fetch_client.fetch_json',
            new=AsyncMock(return_value=[p.as_dict() for p in positions]),
        ):
            result = await fetch_positions_from_ipfs(block_number=BLOCK)

        assert len(result) == 3
        assert [p.leaf_shares for p in result] == [Wei(100), Wei(200), Wei(300)]

    @pytest.mark.parametrize('block', [BlockNumber(1), BlockNumber(999)])
    async def test_block_number_forwarded_to_contract(self, block):
        mock_redeemable = AsyncMock(return_value=create_redeemable_positions(ipfs_hash=''))
        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=mock_redeemable,
        ):
            await fetch_positions_from_ipfs(block_number=block)

        mock_redeemable.assert_called_once_with(block_number=block)


class TestFetchPositionsFromIpfsCached:
    async def test_cache_valid_returns_cached_without_ipfs_fetch(self):
        cache = IpfsPositionsCache()
        cached = [make_position()]
        cache.nonce = NONCE
        cache.checkpoint_block = BLOCK
        cache.data = cached

        mock_ipfs = AsyncMock()
        with patch(f'{MODULE}.ipfs_fetch_client.fetch_json', new=mock_ipfs):
            result = await cached_fetch_positions_from_ipfs(nonce=NONCE, block_number=BLOCK)

        assert result is cached
        mock_ipfs.assert_not_called()

    async def test_cache_invalid_fetches_from_ipfs(self):
        pos = make_position(leaf_shares=888)
        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=AsyncMock(return_value=create_redeemable_positions()),
        ), patch(
            f'{MODULE}.ipfs_fetch_client.fetch_json',
            new=AsyncMock(return_value=[pos.as_dict()]),
        ):
            result = await cached_fetch_positions_from_ipfs(nonce=NONCE, block_number=BLOCK)

        assert len(result) == 1
        assert result[0].leaf_shares == pos.leaf_shares


class TestIterProcessedShares:
    async def test_empty_positions(self):
        results = [
            v async for v in iter_processed_shares([], nonce=1, block_number=BlockNumber(10))
        ]
        assert results == []

    async def test_single_batch(self):
        positions = [make_position(leaf_shares=w) for w in [100, 200, 300]]
        with mock.patch.object(
            os_token_redeemer_contract,
            'multicall_leaf_to_processed_shares',
            new=self._mock_multicall([50, 200, 0]),
        ):
            results = [
                v
                async for v in iter_processed_shares(
                    positions, nonce=3, block_number=BlockNumber(10)
                )
            ]
        assert results == [Wei(50), Wei(200), Wei(0)]

    async def test_two_batches(self):
        first_batch = [make_position(leaf_shares=1000) for _ in range(OS_TOKEN_REDEEMER_CHUNK_SIZE)]
        second_batch = [make_position(leaf_shares=2000) for _ in range(5)]
        positions = first_batch + second_batch

        half = OS_TOKEN_REDEEMER_CHUNK_SIZE // 2
        batch1_processed = [1000] * half + [0] * (OS_TOKEN_REDEEMER_CHUNK_SIZE - half)
        batch2_processed = [0] * 5

        multicall_mock = self._mock_multicall(batch1_processed, batch2_processed)
        with mock.patch.object(
            os_token_redeemer_contract, 'multicall_leaf_to_processed_shares', new=multicall_mock
        ):
            results = [
                v
                async for v in iter_processed_shares(
                    positions, nonce=5, block_number=BlockNumber(10)
                )
            ]

        assert len(results) == OS_TOKEN_REDEEMER_CHUNK_SIZE + 5
        assert results[:OS_TOKEN_REDEEMER_CHUNK_SIZE] == [Wei(v) for v in batch1_processed]
        assert results[OS_TOKEN_REDEEMER_CHUNK_SIZE:] == [Wei(v) for v in batch2_processed]
        assert multicall_mock.call_count == 2

    def _mock_multicall(self, *batch_results: list[int]):
        return mock.AsyncMock(side_effect=[[Wei(v) for v in batch] for batch in batch_results])


class TestCachedIterProcessedShares:
    async def test_cache_hit(self):
        positions = [make_position(leaf_shares=w) for w in [100, 200]]
        nonce = 5
        block_number = BlockNumber(10)

        cache = ProcessedSharesCache()
        cache.nonce = nonce
        cache.checkpoint_block = block_number
        cache.data = {
            Web3.to_hex(p.leaf_hash(nonce - 1)): Wei(p.leaf_shares - 10) for p in positions
        }

        with mock.patch.object(cache, 'is_valid_on', mock.AsyncMock(return_value=True)):
            results = [
                v async for v in cached_iter_processed_shares(positions, nonce, block_number)
            ]

        assert results == [Wei(90), Wei(190)]

    async def test_cache_miss_delegates_to_iter(self):
        positions = [make_position(leaf_shares=1000)]
        nonce = 5
        block_number = BlockNumber(10)

        cache = ProcessedSharesCache()

        async def _fake_iter(*_):
            yield Wei(999)

        with mock.patch.object(
            cache, 'is_valid_on', mock.AsyncMock(return_value=False)
        ), mock.patch(f'{MODULE}.iter_processed_shares', new=_fake_iter):
            results = [
                v async for v in cached_iter_processed_shares(positions, nonce, block_number)
            ]

        assert results == [Wei(999)]
