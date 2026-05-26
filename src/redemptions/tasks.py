import logging
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import cast

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import OsTokenConverter
from sw_utils.typings import ChainHead, ProtocolConfig
from web3 import Web3
from web3.types import Wei

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import os_token_redeemer_contract
from src.common.protocol_config import get_protocol_config
from src.common.typings import Singleton
from src.config.settings import settings
from src.redemptions.os_token_converter import create_os_token_converter
from src.redemptions.typings import OsTokenPosition

logger = logging.getLogger(__name__)

batch_size = 20
ZERO_MERKLE_ROOT = HexStr('0x' + '0' * 64)


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
        position_iter = iter(positions)
        async for processed_shares in iter_processed_shares(positions, nonce, block_number):
            position = next(position_iter)
            cache.data[Web3.to_hex(position.leaf_hash(nonce - 1))] = processed_shares
    cache.checkpoint_block = block_number


async def get_redemption_assets(chain_head: ChainHead) -> Wei:
    """
    Get redemption assets for operator's vault.
    For Gno networks return value in GNO-Wei.
    """
    nonce = await os_token_redeemer_contract.nonce(chain_head.block_number)
    if nonce == 0:
        logger.info('Zero nonce for redemption. Skipping redemption assets.')
        return Wei(0)

    protocol_config = await get_protocol_config()
    vault_to_redemption_assets = await get_vault_to_redemption_assets_direct(
        chain_head=chain_head, nonce=nonce, protocol_config=protocol_config
    )
    return vault_to_redemption_assets[settings.vault]


async def get_vault_to_redemption_assets_direct(
    chain_head: ChainHead, nonce: int, protocol_config: ProtocolConfig
) -> defaultdict[ChecksumAddress, Wei]:
    """
    Get redemption assets per vault, based only on assets directly assigned
    to each vault in the IPFS redeemable positions file. Meta vault assets are
    not yet distributed across their sub-vault tree.

    For Gno networks return value is in GNO-Wei.
    """
    queued_shares = await os_token_redeemer_contract.queued_shares(
        block_number=chain_head.block_number
    )
    os_token_converter = await create_os_token_converter(chain_head.block_number)
    total_redemption_assets = os_token_converter.to_assets(queued_shares)

    # OsToken in-protocol rate may increase while vault assets are exiting.
    # Ensure sufficient assets are allocated for redemption by applying
    # a conservative APR adjustment.
    total_redemption_assets = Wei(
        int(total_redemption_assets * protocol_config.os_token_redeem_multiplier)
    )

    vault_to_redemption_assets = await aggregate_redemption_assets_by_vaults(
        total_redemption_assets,
        nonce=nonce,
        os_token_converter=os_token_converter,
        block_number=chain_head.block_number,
    )
    return vault_to_redemption_assets


async def aggregate_redemption_assets_by_vaults(
    total_redemption_assets: Wei,
    nonce: int,
    os_token_converter: OsTokenConverter,
    block_number: BlockNumber,
) -> defaultdict[ChecksumAddress, Wei]:
    """
    Iterate through redeemable positions until the total redemption assets are exhausted.
    Aggregate unprocessed assets by vaults.

    :param total_redemption_assets: The total amount of assets available for redemption.
    For Gno networks total_redemption_assets is in GNO-Wei.

    :return: A mapping of vault addresses to their corresponding unprocessed assets.
    """
    # Convert total redemption assets to shares
    total_redemption_shares = os_token_converter.to_shares(total_redemption_assets)

    positions = await fetch_positions_from_ipfs(block_number=block_number)
    cut_off_positions = await cut_off_redeemable_positions(
        positions,
        nonce=nonce,
        total_redemption_shares=total_redemption_shares,
        block_number=block_number,
    )

    # Aggregate unprocessed shares by vault
    vault_to_unprocessed_shares: defaultdict[ChecksumAddress, Wei] = defaultdict(lambda: Wei(0))
    for position in cut_off_positions:
        vault_to_unprocessed_shares[position.vault] += position.unprocessed_shares  # type: ignore

    # Convert shares to assets per vault
    return defaultdict(
        lambda: Wei(0),
        {
            vault: os_token_converter.to_assets(shares)
            for vault, shares in vault_to_unprocessed_shares.items()
        },
    )


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


async def cut_off_redeemable_positions(
    all_positions: list[OsTokenPosition],
    nonce: int,
    total_redemption_shares: Wei,
    block_number: BlockNumber,
) -> list[OsTokenPosition]:
    """
    Fill positions with their unprocessed shares until the cumulative total reaches
    total_redemption_shares, then stop. The last included position's unprocessed_shares
    is capped so the cumulative total does not exceed total_redemption_shares.
    Fully processed positions (no remaining unprocessed shares) are omitted from
    the returned list.
    """
    redeemable: list[OsTokenPosition] = []
    remaining_shares = total_redemption_shares
    position_iter = iter(all_positions)

    async for processed_shares in cached_iter_processed_shares(all_positions, nonce, block_number):
        position = next(position_iter)
        unprocessed_shares = position.leaf_shares - processed_shares
        # Skip fully processed positions; tolerate 1 wei rounding error.
        if unprocessed_shares <= 1:
            continue

        unprocessed_shares = min(unprocessed_shares, remaining_shares)
        redeemable.append(
            OsTokenPosition(
                owner=position.owner,
                vault=position.vault,
                leaf_shares=position.leaf_shares,
                unprocessed_shares=Wei(unprocessed_shares),
            )
        )
        remaining_shares -= unprocessed_shares  # type: ignore
        if remaining_shares <= 0:
            return redeemable

    return redeemable


async def cached_iter_processed_shares(
    positions: list[OsTokenPosition],
    nonce: int,
    block_number: BlockNumber,
) -> AsyncIterator[Wei]:
    cache = ProcessedSharesCache()
    if await cache.is_valid_on(nonce, block_number):
        for position in positions:
            leaf_hash = Web3.to_hex(position.leaf_hash(nonce - 1))
            yield cast(Wei, cache.data[leaf_hash])
        return
    async for shares in iter_processed_shares(positions, nonce, block_number):
        yield shares


async def iter_processed_shares(
    positions: list[OsTokenPosition],
    nonce: int,
    block_number: BlockNumber,
) -> AsyncIterator[Wei]:
    for i in range(0, len(positions), batch_size):
        batch = positions[i : i + batch_size]
        calls = [
            os_token_redeemer_contract.encode_abi('leafToProcessedShares', [p.leaf_hash(nonce - 1)])
            for p in batch
        ]
        rpc_results = await os_token_redeemer_contract.contract.functions.multicall(calls).call(
            block_identifier=block_number
        )
        for res in rpc_results:
            yield Wei(Web3.to_int(res))
