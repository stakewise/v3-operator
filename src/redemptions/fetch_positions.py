import asyncio
from collections.abc import AsyncIterator
from typing import cast

import aioitertools
from eth_typing import BlockNumber, HexStr
from web3 import Web3
from web3.types import Wei

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import os_token_redeemer_contract
from src.common.typings import Singleton
from src.config.settings import settings
from src.redemptions.typings import OsTokenPosition

batch_size = 20
ZERO_MERKLE_ROOT = HexStr('0x' + '0' * 64)

_update_cache_lock = asyncio.Lock()


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


async def update_processed_shares_cache() -> None:
    """Validate and update the processed shares cache to the current finalized block."""
    async with _update_cache_lock:
        await _update_processed_shares_cache()


async def _update_processed_shares_cache() -> None:
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
            yield Wei(Web3.to_int(res))


async def fetch_positions_from_ipfs(
    block_number: BlockNumber,
) -> list[OsTokenPosition]:
    redeemable_positions = await os_token_redeemer_contract.redeemable_positions(
        block_number=block_number
    )

    # Check whether redeemable positions are available
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
        )
        for item in data
    ]
