import logging
from collections import defaultdict
from dataclasses import replace

from eth_typing import BlockNumber, ChecksumAddress
from sw_utils import OsTokenConverter
from sw_utils.typings import ChainHead, ProtocolConfig
from web3.types import Wei

from src.common.contracts import os_token_redeemer_contract
from src.common.protocol_config import get_protocol_config
from src.config.settings import settings
from src.redemptions.fetch_positions import (
    fetch_positions_with_processed_shares,
    update_processed_shares_cache,
)
from src.redemptions.os_token_converter import create_os_token_converter
from src.redemptions.typings import OsTokenPosition

logger = logging.getLogger(__name__)


async def get_redemption_assets(chain_head: ChainHead) -> Wei:
    """
    Get redemption assets for operator's vault.
    For Gno networks return value in GNO-Wei.
    """
    nonce = await os_token_redeemer_contract.nonce(chain_head.block_number)
    if nonce == 0:
        logger.info('Zero nonce for redemption. Skipping redemption assets.')
        return Wei(0)

    await update_processed_shares_cache()
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
    Aggregate shares_to_redeem by vault and convert to assets.

    :param total_redemption_assets: The total amount of assets available for redemption.
    For Gno networks total_redemption_assets is in GNO-Wei.

    :return: A mapping of vault addresses to their corresponding assets to redeem.
    """
    # Convert total redemption assets to shares
    total_redemption_shares = os_token_converter.to_shares(total_redemption_assets)

    positions = await fetch_positions_with_processed_shares(nonce=nonce, block_number=block_number)
    positions = await assign_shares_to_redeem(
        positions,
        total_redemption_shares=total_redemption_shares,
    )

    # Aggregate shares_to_redeem by vault
    vault_to_shares_to_redeem: defaultdict[ChecksumAddress, Wei] = defaultdict(lambda: Wei(0))
    for position in positions:
        vault_to_shares_to_redeem[position.vault] += position.shares_to_redeem  # type: ignore

    # Convert shares to assets per vault
    return defaultdict(
        lambda: Wei(0),
        {
            vault: os_token_converter.to_assets(shares)
            for vault, shares in vault_to_shares_to_redeem.items()
        },
    )


async def assign_shares_to_redeem(
    positions: list[OsTokenPosition],
    total_redemption_shares: Wei,
) -> list[OsTokenPosition]:
    """
    Iterate pre-enriched positions (processed_shares already set from on-chain) and set
    shares_to_redeem on each, stopping once the budget is exhausted.

    Rules:
    - Fully processed positions (unprocessed_shares <= 1) are skipped.
    - Each position's shares_to_redeem is set to min(unprocessed_shares, remaining_budget).
    - Iteration stops as soon as the cumulative shares_to_redeem reaches total_redemption_shares.
    """
    if total_redemption_shares <= 0:
        return []

    redeemable: list[OsTokenPosition] = []
    remaining_shares = total_redemption_shares

    for position in positions:
        unprocessed_shares = position.unprocessed_shares
        # Skip fully processed positions; tolerate 1 wei rounding error.
        if unprocessed_shares <= 1:
            continue

        capped_unprocessed = Wei(min(unprocessed_shares, remaining_shares))
        redeemable.append(replace(position, shares_to_redeem=capped_unprocessed))
        remaining_shares -= capped_unprocessed  # type: ignore
        if remaining_shares <= 0:
            return redeemable

    return redeemable
