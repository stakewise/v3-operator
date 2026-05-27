import aioitertools
from eth_typing import BlockNumber, HexStr
from web3 import Web3
from web3.types import Wei

from src.common.clients import execution_client
from src.common.contracts import os_token_redeemer_contract
from src.common.typings import Singleton
from src.config.settings import settings


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
    from src.redemptions.tasks import fetch_positions_from_ipfs, iter_processed_shares

    finalized_block = await execution_client.eth.get_block('finalized')
    block_number = BlockNumber(finalized_block['number'])

    cache = ProcessedSharesCache()
    if cache.checkpoint_block == block_number:
        return

    nonce = await os_token_redeemer_contract.nonce(block_number)
    if nonce == 0:
        cache.nonce = nonce
        cache.checkpoint_block = block_number
        return

    if not await cache.is_valid_on(nonce, block_number):
        cache.nonce = nonce
        cache.data.clear()
        positions = await fetch_positions_from_ipfs(block_number=block_number)
        async for position, processed_shares in aioitertools.zip(
            positions, iter_processed_shares(positions, nonce, block_number)
        ):
            leaf_hash = Web3.to_hex(position.leaf_hash(nonce - 1))
            cache.data[leaf_hash] = processed_shares
    cache.checkpoint_block = block_number
