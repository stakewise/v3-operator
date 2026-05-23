import logging
from collections import defaultdict
from typing import cast

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import OsTokenConverter
from sw_utils.typings import ChainHead, ProtocolConfig
from web3 import Web3
from web3.types import Wei

from src.common.clients import ipfs_fetch_client
from src.common.contracts import multicall_contract, os_token_redeemer_contract
from src.common.protocol_config import get_protocol_config
from src.config.settings import settings
from src.redemptions.os_token_converter import create_os_token_converter
from src.redemptions.typings import OsTokenPosition

logger = logging.getLogger(__name__)


batch_size = 20
ZERO_MERKLE_ROOT = HexStr('0x' + '0' * 64)


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

    # The contract increments the nonce at the end of setRedeemablePositions,
    # so use the previous nonce for leaf hash computation.
    vault_to_redemption_assets = await get_vault_to_redemption_assets_direct(
        chain_head=chain_head, tree_nonce=nonce - 1, protocol_config=protocol_config
    )
    return vault_to_redemption_assets[settings.vault]


async def get_vault_to_redemption_assets_direct(
    chain_head: ChainHead, tree_nonce: int, protocol_config: ProtocolConfig
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
        tree_nonce=tree_nonce,
        os_token_converter=os_token_converter,
        block_number=chain_head.block_number,
    )
    return vault_to_redemption_assets


async def aggregate_redemption_assets_by_vaults(
    total_redemption_assets: Wei,
    tree_nonce: int,
    os_token_converter: OsTokenConverter,
    block_number: BlockNumber | None = None,
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

    vault_to_unprocessed_shares: defaultdict[ChecksumAddress, Wei] = defaultdict(lambda: Wei(0))

    # Iterate through redeemable positions until total redemption shares are exhausted
    positions = await fetch_positions_from_ipfs(block_number=block_number)
    redeemable_positions = await calculate_redeemable_shares(
        positions, nonce=tree_nonce, block_number=block_number
    )
    for position in redeemable_positions:
        # Skip rounding errors
        if position.unprocessed_shares <= 1:
            continue

        # Aggregate unprocessed shares by vault
        unprocessed_shares = min(position.unprocessed_shares, total_redemption_shares)
        vault_to_unprocessed_shares[position.vault] += unprocessed_shares  # type: ignore

        total_redemption_shares -= unprocessed_shares  # type: ignore

        if total_redemption_shares <= 0:
            break

    # Convert shares to assets per vault
    return defaultdict(
        lambda: Wei(0),
        {
            vault: os_token_converter.to_assets(shares)
            for vault, shares in vault_to_unprocessed_shares.items()
        },
    )


async def fetch_positions_from_ipfs(
    block_number: BlockNumber | None = None,
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


async def calculate_redeemable_shares(
    all_positions: list[OsTokenPosition],
    nonce: int,
    block_number: BlockNumber | None = None,
) -> list[OsTokenPosition]:
    """Query processed shares and return positions with available_shares > 0."""
    redeemable: list[OsTokenPosition] = []

    for i in range(0, len(all_positions), batch_size):
        batch = all_positions[i : i + batch_size]
        processed_shares_batch = await get_processed_shares_batch(
            os_token_positions_batch=batch,
            nonce=nonce,
            block_number=block_number,
        )
        for position, processed_shares in zip(batch, processed_shares_batch):
            unprocessed_shares = position.leaf_shares - processed_shares
            if unprocessed_shares <= 0:
                continue
            redeemable.append(
                OsTokenPosition(
                    owner=position.owner,
                    vault=position.vault,
                    leaf_shares=position.leaf_shares,
                    unprocessed_shares=Wei(unprocessed_shares),
                )
            )

    return redeemable


async def get_processed_shares_batch(
    os_token_positions_batch: list[OsTokenPosition],
    nonce: int,
    block_number: BlockNumber | None = None,
) -> list[Wei]:
    calls: list[tuple[ChecksumAddress, HexStr]] = []

    for os_token_position in os_token_positions_batch:
        leaf_hash = os_token_position.leaf_hash(nonce)
        call_data = os_token_redeemer_contract.encode_abi(
            fn_name='leafToProcessedShares',
            args=[leaf_hash],
        )
        calls.append((os_token_redeemer_contract.contract_address, call_data))

    _, results = await multicall_contract.aggregate(calls, block_number=block_number)
    return [Wei(Web3.to_int(res)) for res in results]
