import asyncio
import functools
from collections.abc import AsyncIterator, Callable
from typing import Any, cast

import aioitertools
from eth_typing import BlockNumber, HexStr
from web3 import Web3
from web3.types import Wei

from src.common.clients import ipfs_fetch_client
from src.common.typings import Singleton
from src.config.settings import OS_TOKEN_REDEEMER_CHUNK_SIZE, settings
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.typings import OsTokenPosition

ZERO_MERKLE_ROOT = HexStr('0x' + '0' * 64)


# Shared lock guarding both caches so updates and validity reads don't race.
_cache_lock = asyncio.Lock()


def with_lock(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        async with _cache_lock:
            return await func(*args, **kwargs)

    return wrapper


class IpfsPositionsCache(metaclass=Singleton):
    def __init__(self) -> None:
        self.nonce: int | None = None
        self.checkpoint_block: BlockNumber | None = None
        self.data: list[OsTokenPosition] = []

    def is_valid_for(self, nonce: int) -> bool:
        return self.nonce == nonce


class ProcessedSharesCache(metaclass=Singleton):
    def __init__(self) -> None:
        self.nonce: int | None = None
        self.checkpoint_block: BlockNumber | None = None
        self.data: dict[HexStr, Wei] = {}

    async def is_valid_on(self, nonce: int, block_number: BlockNumber) -> bool:
        if self.nonce != nonce:
            return False
        if self.checkpoint_block == block_number:
            return True
        if self.checkpoint_block is not None and self.checkpoint_block > block_number:
            # Probably logic error if cache checkpoint block is in the future compared
            # to the given block number
            return False
        from_block = (
            BlockNumber(self.checkpoint_block + 1)
            if self.checkpoint_block is not None
            else settings.network_config.OS_TOKEN_REDEEMER_GENESIS_BLOCK
        )
        events = await os_token_redeemer_contract.get_os_token_positions_redeemed_events(
            from_block=from_block, to_block=block_number
        )
        return not events


@with_lock
async def update_positions_cache(block_number: BlockNumber) -> None:
    """Update the IPFS positions cache to the given finalized block."""
    cache = IpfsPositionsCache()
    if cache.checkpoint_block == block_number:
        return

    nonce = await os_token_redeemer_contract.nonce(block_number)
    if nonce == 0:
        cache.nonce = nonce
        cache.data = []
        cache.checkpoint_block = block_number
        return

    if not cache.is_valid_for(nonce):
        cache.data = await fetch_positions_from_ipfs(block_number=block_number)
        cache.nonce = nonce
    cache.checkpoint_block = block_number


@with_lock
async def update_processed_shares_cache(block_number: BlockNumber) -> None:
    """Update the processed shares cache to the given finalized block."""
    cache = ProcessedSharesCache()
    if cache.checkpoint_block == block_number:
        return

    nonce = await os_token_redeemer_contract.nonce(block_number)
    if nonce == 0:
        cache.nonce = nonce
        cache.data = {}
        cache.checkpoint_block = block_number
        return

    if not await cache.is_valid_on(nonce, block_number):
        positions = await cached_fetch_positions_from_ipfs(nonce=nonce, block_number=block_number)
        data: dict[HexStr, Wei] = {}
        async for position, processed_shares in aioitertools.zip(
            positions, iter_processed_shares(positions, nonce, block_number)
        ):
            leaf_hash = Web3.to_hex(position.leaf_hash(nonce - 1))
            data[leaf_hash] = processed_shares
        cache.nonce = nonce
        cache.data = data
    cache.checkpoint_block = block_number


async def fetch_positions_with_processed_shares(
    nonce: int,
    block_number: BlockNumber,
) -> list[OsTokenPosition]:
    """Fetch positions from IPFS (cached) and enrich each with its processed_shares."""
    positions = await cached_fetch_positions_from_ipfs(nonce=nonce, block_number=block_number)
    enriched: list[OsTokenPosition] = []
    async for position, processed_shares in aioitertools.zip(
        positions, cached_iter_processed_shares(positions, nonce, block_number)
    ):
        enriched.append(
            OsTokenPosition(
                owner=position.owner,
                vault=position.vault,
                leaf_shares=position.leaf_shares,
                index=position.index,
                processed_shares=processed_shares,
            )
        )
    return enriched


async def cached_iter_processed_shares(
    positions: list[OsTokenPosition],
    nonce: int,
    block_number: BlockNumber,
) -> AsyncIterator[Wei]:
    cache = ProcessedSharesCache()
    # Cache was last populated at a finalized block;
    # verify it's still valid at the current (possibly newer) block.
    # Hold the shared lock while checking validity and snapshotting the cached
    # values so a concurrent cache update can't change them mid-read.
    cached_shares: list[Wei] = []
    async with _cache_lock:
        cache_is_valid = await cache.is_valid_on(nonce, block_number)
        if cache_is_valid:
            for position in positions:
                leaf_hash = Web3.to_hex(position.leaf_hash(nonce - 1))
                cached_shares.append(cache.data[leaf_hash])

    if cache_is_valid:
        for shares in cached_shares:
            yield shares
        return
    async for shares in iter_processed_shares(positions, nonce, block_number):
        yield shares


async def iter_processed_shares(
    positions: list[OsTokenPosition],
    nonce: int,
    block_number: BlockNumber,
) -> AsyncIterator[Wei]:
    """Fetch processed shares via batched multicalls, yielding one value per position.
    The generator flattens batch results so callers see a flat stream aligned with positions."""
    for i in range(0, len(positions), OS_TOKEN_REDEEMER_CHUNK_SIZE):
        batch = positions[i : i + OS_TOKEN_REDEEMER_CHUNK_SIZE]
        rpc_results = await os_token_redeemer_contract.multicall_leaf_to_processed_shares(
            batch, nonce, block_number
        )
        for res in rpc_results:
            yield res


async def cached_fetch_positions_from_ipfs(
    nonce: int,
    block_number: BlockNumber,
) -> list[OsTokenPosition]:
    """Return cached positions if still valid for the given nonce and block, otherwise fetch."""
    cache = IpfsPositionsCache()
    if cache.is_valid_for(nonce):
        return cache.data
    return await fetch_positions_from_ipfs(block_number=block_number)


async def fetch_positions_from_ipfs(
    block_number: BlockNumber,
) -> list[OsTokenPosition]:
    """Fetch redeemable positions from IPFS. No caching."""
    redeemable_positions = await os_token_redeemer_contract.redeemable_positions(
        block_number=block_number
    )

    if not redeemable_positions.ipfs_hash:
        return []
    if redeemable_positions.merkle_root == ZERO_MERKLE_ROOT:
        return []

    # Fetch redeemable positions data from IPFS
    data = cast(list[dict], await ipfs_fetch_client.fetch_json(redeemable_positions.ipfs_hash))

    # data structure example:
    # [{"owner:" 0x01, "leaf_shares": 100000, "vault": 0x02}, ...]

    return [
        OsTokenPosition(
            owner=Web3.to_checksum_address(item['owner']),
            vault=Web3.to_checksum_address(item['vault']),
            leaf_shares=Wei(int(item['leaf_shares'])),
            index=index,
        )
        for index, item in enumerate(data)
    ]
