import logging
from collections import defaultdict

from eth_typing import BlockNumber
from gql import gql
from web3 import Web3
from web3.types import ChecksumAddress, Wei

from src.common.clients import graph_client
from src.redemptions.typings import (
    Allocator,
    LeverageStrategyPosition,
    VaultOsTokenPosition,
)

logger = logging.getLogger(__name__)


async def graph_get_allocators(block_number: BlockNumber) -> list[Allocator]:
    """
    Fetch allocators at the given block. First fetches vaults eligible for
    redemption (excluding legacy and meta vaults), then fetches allocators
    per vault.
    """
    vaults = await graph_get_redeemable_vaults(block_number)
    return await graph_get_redeemable_allocators_from_vaults(vaults, block_number)


async def graph_get_redeemable_vaults(block_number: BlockNumber) -> list[ChecksumAddress]:
    """
    Fetch vaults eligible for redemption at the given block, excluding legacy
    vaults (osTokenConfig.id == '1') and meta vaults.
    """
    query = gql(
        """
        query vaultsQuery($block: Int, $first: Int, $lastID: String) {
          vaults(
            block: {number: $block},
            where: {id_gt: $lastID, osTokenConfig_not: "1", isMetaVault: false},
            orderBy: id,
            first: $first
          ) {
            id
          }
        }
        """
    )
    params = {'block': block_number}
    response = await graph_client.fetch_pages(query, params=params, cursor_pagination=True)
    return [Web3.to_checksum_address(item['id']) for item in response]


async def graph_get_redeemable_allocators_from_vaults(
    vaults: list[ChecksumAddress],
    block_number: BlockNumber,
) -> list[Allocator]:
    """
    Fetch allocators at the given block for each vault in ``vaults`` and
    return them as a list of Allocator objects. Filters records to include
    only those with mintedOsTokenShares > 0.
    """
    query = gql(
        """
        query getAllocators($block: Int, $first: Int, $lastID: String, $vault: String){
          allocators(
            block: {number: $block},
            where: {
                id_gt: $lastID,
                vault: $vault,
                mintedOsTokenShares_gt: 0
            },
            orderBy: id
            first: $first
          ){
            id
            address
            mintedOsTokenShares
            ltv
          }
        }
        """
    )
    positions_by_allocator: defaultdict[str, list[VaultOsTokenPosition]] = defaultdict(list)
    total = len(vaults)
    for index, vault in enumerate(vaults, start=1):
        params = {
            'block': block_number,
            'vault': vault.lower(),
        }
        logger.debug(
            'graph_get_redeemable_allocators_from_vaults: querying vault %s (%d/%d)',
            vault,
            index,
            total,
        )
        response = await graph_client.fetch_pages(query, params=params, cursor_pagination=True)
        for item in response:
            positions_by_allocator[item['address']].append(
                VaultOsTokenPosition(
                    address=vault,
                    minted_shares=Wei(int(item['mintedOsTokenShares'])),
                    ltv=float(item['ltv']),
                )
            )
    return [
        Allocator(
            address=Web3.to_checksum_address(allocator_address),
            vault_os_token_positions=vault_os_token_positions,
        )
        for allocator_address, vault_os_token_positions in positions_by_allocator.items()
    ]


async def graph_get_leverage_positions(block_number: BlockNumber) -> list[LeverageStrategyPosition]:
    query = gql(
        """
        query PositionsQuery($block: Int,  $first: Int, $skip: Int) {
          leverageStrategyPositions(
            block: { number: $block },
            orderBy: id,
            first: $first
            skip: $skip
          ) {
            user
            proxy
            vault {
              id
            }
            osTokenShares
            exitingOsTokenShares
            assets
            exitingAssets
          }
        }
        """
    )
    params = {'block': block_number}
    response = await graph_client.fetch_pages(query, params=params)
    return [LeverageStrategyPosition.from_graph(item) for item in response]


async def graph_get_os_token_holders(block_number: BlockNumber) -> dict[ChecksumAddress, Wei]:
    query = gql(
        """
        query osTokenHoldersQuery($block: Int,  $first: Int, $skip: Int) {
          osTokenHolders(
            block: { number: $block },
            where:{
              balance_gt: 0
            }
            orderBy: id,
            first: $first
            skip: $skip
          ) {
            id
            balance
          }
        }
        """
    )
    params = {'block': block_number}
    response = await graph_client.fetch_pages(query, params=params)
    return {Web3.to_checksum_address(item['id']): Wei(int(item['balance'])) for item in response}
