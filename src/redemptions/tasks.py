import logging
from collections import defaultdict
from typing import AsyncGenerator, cast

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import convert_to_mgno
from sw_utils.networks import GNO_NETWORKS
from sw_utils.typings import ChainHead, ProtocolConfig
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import ipfs_fetch_client
from src.common.contracts import multicall_contract, os_token_redeemer_contract
from src.common.protocol_config import get_protocol_config
from src.common.utils import async_batched
from src.config.settings import settings
from src.meta_vault.service import distribute_meta_vault_redemption_assets
from src.redemptions.os_token_converter import create_os_token_converter
from src.redemptions.typings import OsTokenPosition

logger = logging.getLogger(__name__)


batch_size = 20
ZERO_MERKLE_ROOT = HexStr('0x' + '0' * 64)


async def get_redemption_assets(chain_head: ChainHead) -> Gwei:
    """
    Get redemption assets for operator's vault.
    For Gno networks return value in mGNO-GWei.
    """
    protocol_config = await get_protocol_config()

    # Aggregate redemption assets per vault
    vault_to_redemption_assets = await get_vault_to_redemption_assets(
        chain_head=chain_head, protocol_config=protocol_config
    )
    # Distribute redemption assets from meta vaults to their underlying vaults
    vault_to_redemption_assets = await distribute_meta_vault_redemption_assets(
        vault_to_redemption_assets=vault_to_redemption_assets,
        block_number=chain_head.block_number,
    )
    # Filter by operator's vault
    redemption_assets = vault_to_redemption_assets[settings.vault]

    if settings.network in GNO_NETWORKS:
        # Convert GNO -> mGNO
        redemption_assets = convert_to_mgno(redemption_assets)

    return Gwei(int(Web3.from_wei(redemption_assets, 'gwei')))


async def get_vault_to_redemption_assets(
    chain_head: ChainHead, protocol_config: ProtocolConfig
) -> defaultdict[ChecksumAddress, Wei]:
    """
    Get redemption assets per vault.
    For Gno networks return value in GNO-Wei.
    """
    ticket = await os_token_redeemer_contract.get_exit_queue_cumulative_tickets(
        block_number=chain_head.block_number
    )

    total_redemption_assets = await os_token_redeemer_contract.get_exit_queue_missing_assets(
        ticket, block_number=chain_head.block_number
    )

    # OsToken in-protocol rate may increase while vault assets are exiting.
    # Ensure sufficient assets are allocated for redemption by applying
    # a conservative APR adjustment.
    total_redemption_assets = Wei(
        int(total_redemption_assets * protocol_config.os_token_redeem_multiplier)
    )

    vault_to_redemption_assets = await aggregate_redemption_assets_by_vaults(
        total_redemption_assets,
        block_number=chain_head.block_number,
    )
    return vault_to_redemption_assets


async def aggregate_redemption_assets_by_vaults(
    total_redemption_assets: Wei, block_number: BlockNumber | None = None
) -> defaultdict[ChecksumAddress, Wei]:
    """
    Iterate through redeemable positions until the total redemption assets are exhausted.
    Aggregate unprocessed assets by vaults.

    :param total_redemption_assets: The total amount of assets available for redemption.
    For Gno networks total_redemption_assets is in GNO-Wei.

    :return: A mapping of vault addresses to their corresponding unprocessed assets.
    """
    # Convert total redemption assets to shares
    os_token_converter = await create_os_token_converter(block_number)
    total_redemption_shares = os_token_converter.to_shares(total_redemption_assets)

    nonce = await os_token_redeemer_contract.nonce(block_number=block_number)
    vault_to_unprocessed_shares: defaultdict[ChecksumAddress, Wei] = defaultdict(lambda: Wei(0))

    # Iterate through redeemable positions until total redemption shares are exhausted
    async for os_token_position_batch in async_batched(
        iter_os_token_positions(block_number=block_number), batch_size
    ):
        processed_shares_batch = await get_processed_shares_batch(
            os_token_positions_batch=os_token_position_batch,
            nonce=nonce,
            block_number=block_number,
        )
        for os_token_position, processed_shares in zip(
            os_token_position_batch, processed_shares_batch
        ):
            vault = os_token_position.vault
            leaf_shares = os_token_position.amount
            unprocessed_shares = leaf_shares - processed_shares

            # Skip if no unprocessed shares, handle rounding errors
            if unprocessed_shares <= 1:
                continue

            # Aggregate unprocessed shares by vault
            unprocessed_shares = min(unprocessed_shares, total_redemption_shares)
            vault_to_unprocessed_shares[vault] += unprocessed_shares  # type: ignore

            total_redemption_shares -= unprocessed_shares  # type: ignore

            # Stop iterating processed shares batch
            if total_redemption_shares <= 0:
                break

        # Stop iterating redeemable positions
        if total_redemption_shares <= 0:
            break

    # Convert shares to assets per vault
    vault_to_unprocessed_assets = defaultdict(lambda: Wei(0))

    for vault, shares in vault_to_unprocessed_shares.items():
        vault_to_unprocessed_assets[vault] = os_token_converter.to_assets(shares)

    return vault_to_unprocessed_assets


async def iter_os_token_positions(
    block_number: BlockNumber | None = None,
) -> AsyncGenerator[OsTokenPosition, None]:
    redeemable_positions = await os_token_redeemer_contract.redeemable_positions(
        block_number=block_number
    )

    # Check whether redeemable positions are available
    if not redeemable_positions.ipfs_hash:
        return
    if redeemable_positions.merkle_root == ZERO_MERKLE_ROOT:
        return
    # Fetch redeemable positions data from IPFS
    data = cast(list[dict], await ipfs_fetch_client.fetch_json(redeemable_positions.ipfs_hash))

    # data structure example:
    # [{"owner:" 0x01, "amount": 100000, "vault": 0x02}, ...]

    for item in data:
        yield OsTokenPosition(
            owner=Web3.to_checksum_address(item['owner']),
            vault=Web3.to_checksum_address(item['vault']),
            amount=Wei(int(item['amount'])),
        )


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
