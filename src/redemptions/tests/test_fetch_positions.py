from unittest import mock
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.config.settings import settings
from src.redemptions.fetch_positions import (
    ZERO_MERKLE_ROOT,
    IpfsPositionsCache,
    ProcessedSharesCache,
    batch_size,
    cached_iter_processed_shares,
    fetch_positions_from_ipfs,
    iter_processed_shares,
    os_token_redeemer_contract,
    update_processed_shares_cache,
)
from src.redemptions.tests.factories import create_redeemable_positions, make_position

MODULE = 'src.redemptions.fetch_positions'
BLOCK = BlockNumber(100)


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

        mock_client = MagicMock()
        mock_client.eth.get_block = self._mock_finalized_block(100)
        with patch(f'{MODULE}.execution_client', new=mock_client):
            await update_processed_shares_cache()

        assert cache.checkpoint_block == BlockNumber(100)

    async def test_zero_nonce_sets_checkpoint(self):
        cache = ProcessedSharesCache()

        mock_client = MagicMock()
        mock_client.eth.get_block = self._mock_finalized_block(100)
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

        mock_client = MagicMock()
        mock_client.eth.get_block = self._mock_finalized_block(100)
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

        mock_client = MagicMock()
        mock_client.eth.get_block = self._mock_finalized_block(100)
        with patch(f'{MODULE}.execution_client', new=mock_client), patch(
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
            await update_processed_shares_cache()

        assert cache.nonce == 5
        assert cache.checkpoint_block == BlockNumber(100)
        expected_key = Web3.to_hex(pos.leaf_hash(4))
        assert cache.data == {expected_key: processed}

    def _mock_finalized_block(self, block_number: int) -> AsyncMock:
        block = MagicMock()
        block.__getitem__ = lambda self, key: block_number if key == 'number' else None
        return AsyncMock(return_value=block)


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

    async def test_cache_hit_returns_cached_data_without_ipfs_fetch(self):
        redeemable = create_redeemable_positions()
        cache = IpfsPositionsCache()
        cached_positions = [make_position()]
        cache.ipfs_hash = redeemable.ipfs_hash
        cache.data = cached_positions

        mock_ipfs = AsyncMock()
        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=AsyncMock(return_value=redeemable),
        ), patch(f'{MODULE}.ipfs_fetch_client.fetch_json', new=mock_ipfs):
            result = await fetch_positions_from_ipfs(block_number=BLOCK)

        assert result is cached_positions
        mock_ipfs.assert_not_called()

    async def test_cache_miss_fetches_ipfs_and_updates_cache(self):
        pos = make_position(leaf_shares=1000, processed_shares=0)
        redeemable = create_redeemable_positions()

        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=AsyncMock(return_value=redeemable),
        ), patch(
            f'{MODULE}.ipfs_fetch_client.fetch_json',
            new=AsyncMock(return_value=[pos.as_dict()]),
        ):
            result = await fetch_positions_from_ipfs(block_number=BLOCK)

        assert len(result) == 1
        assert result[0].owner == pos.owner
        assert result[0].vault == pos.vault
        assert result[0].leaf_shares == pos.leaf_shares
        assert result[0].processed_shares == Wei(0)

        cache = IpfsPositionsCache()
        assert cache.ipfs_hash == redeemable.ipfs_hash
        assert cache.data == result

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

    async def test_different_ipfs_hash_refetches_and_updates_cache(self):
        old_hash = faker.ipfs_hash()
        cache = IpfsPositionsCache()
        cache.ipfs_hash = old_hash
        cache.data = []

        redeemable = create_redeemable_positions()
        assert redeemable.ipfs_hash != old_hash

        pos = make_position(leaf_shares=777, processed_shares=0)

        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=AsyncMock(return_value=redeemable),
        ), patch(
            f'{MODULE}.ipfs_fetch_client.fetch_json',
            new=AsyncMock(return_value=[pos.as_dict()]),
        ):
            result = await fetch_positions_from_ipfs(block_number=BLOCK)

        assert len(result) == 1
        assert result[0].leaf_shares == pos.leaf_shares
        assert cache.ipfs_hash == redeemable.ipfs_hash

    @pytest.mark.parametrize('block', [BlockNumber(1), BlockNumber(999)])
    async def test_block_number_forwarded_to_contract(self, block):
        mock_redeemable = AsyncMock(return_value=create_redeemable_positions(ipfs_hash=''))
        with patch(
            f'{MODULE}.os_token_redeemer_contract.redeemable_positions',
            new=mock_redeemable,
        ):
            await fetch_positions_from_ipfs(block_number=block)

        mock_redeemable.assert_called_once_with(block_number=block)


def encode_wei(value: int) -> bytes:
    return value.to_bytes(32, 'big')


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
        first_batch = [make_position(leaf_shares=1000) for _ in range(batch_size)]
        second_batch = [make_position(leaf_shares=2000) for _ in range(5)]
        positions = first_batch + second_batch

        half = batch_size // 2
        batch1_processed = [1000] * half + [0] * (batch_size - half)
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

        assert len(results) == batch_size + 5
        assert results[:batch_size] == [Wei(v) for v in batch1_processed]
        assert results[batch_size:] == [Wei(v) for v in batch2_processed]
        assert multicall_mock.call_count == 2

    def _mock_multicall(self, *batch_results: list[int]):
        return mock.AsyncMock(
            side_effect=[[encode_wei(v) for v in batch] for batch in batch_results]
        )


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
