import asyncio
import functools
from collections.abc import AsyncIterator, Callable
from typing import Any, cast

import aioitertools
from eth_typing import BlockNumber, HexStr
from web3 import Web3
from web3.types import Wei

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import os_token_redeemer_contract
from src.common.typings import Singleton
from src.config.settings import settings
from src.redemptions.typings import OsTokenPosition

batch_size = 1000
ZERO_MERKLE_ROOT = HexStr('0x' + '0' * 64)


def with_lock(func: Callable[..., Any]) -> Callable[..., Any]:
    lock = asyncio.Lock()

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        async with lock:
            return await func(*args, **kwargs)

    return wrapper


class IpfsPositionsCache(metaclass=Singleton):
    def __init__(self) -> None:
        self.ipfs_hash: str | None = None
        self.data: list[OsTokenPosition] = []


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
async def update_processed_shares_cache() -> None:
    """Validate and update the processed shares cache to the current finalized block."""
    finalized_block = await execution_client.eth.get_block('finalized')
    block_number = BlockNumber(finalized_block['number'])

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
        positions = await fetch_positions_from_ipfs(block_number=block_number)
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
    positions = await fetch_positions_from_ipfs(block_number=block_number)
    enriched: list[OsTokenPosition] = []
    async for position, processed_shares in aioitertools.zip(
        positions, cached_iter_processed_shares(positions, nonce, block_number)
    ):
        enriched.append(
            OsTokenPosition(
                owner=position.owner,
                vault=position.vault,
                leaf_shares=position.leaf_shares,
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
    if await cache.is_valid_on(nonce, block_number):
        for position in positions:
            leaf_hash = Web3.to_hex(position.leaf_hash(nonce - 1))
            yield cache.data[leaf_hash]
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
    for i in range(0, len(positions), batch_size):
        batch = positions[i : i + batch_size]
        rpc_results = await os_token_redeemer_contract.multicall_leaf_to_processed_shares(
            batch, nonce, block_number
        )
        for res in rpc_results:
            yield res


@with_lock
async def fetch_positions_from_ipfs(
    block_number: BlockNumber,
) -> list[OsTokenPosition]:
    """
    Fetch redeemable positions from IPFS for the given block.
    Results are cached by IPFS hash.
    """
    redeemable_positions = await os_token_redeemer_contract.redeemable_positions(
        block_number=block_number
    )

    # Check whether redeemable positions are available
    if not redeemable_positions.ipfs_hash:
        return []
    if redeemable_positions.merkle_root == ZERO_MERKLE_ROOT:
        return []

    cache = IpfsPositionsCache()
    if cache.ipfs_hash == redeemable_positions.ipfs_hash:
        return cache.data

    # Fetch redeemable positions data from IPFS
    data = cast(list[dict], await ipfs_fetch_client.fetch_json(redeemable_positions.ipfs_hash))

    # data structure example:
    # [{"owner:" 0x01, "leaf_shares": 100000, "vault": 0x02}, ...]

    positions = [
        OsTokenPosition(
            owner=Web3.to_checksum_address(item['owner']),
            vault=Web3.to_checksum_address(item['vault']),
            leaf_shares=Wei(int(item['leaf_shares'])),
        )
        for item in data
    ]
    cache.ipfs_hash = redeemable_positions.ipfs_hash
    cache.data = positions
    return positions
