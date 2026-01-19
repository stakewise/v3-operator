import logging
from collections import defaultdict

from eth_typing import BlockNumber
from gql import gql
from web3 import Web3
from web3.types import Wei

from src.common.clients import graph_client
from src.redeem.typings import Allocator, LeverageStrategyPosition, VaultShares

logger = logging.getLogger(__name__)


async def graph_get_allocators(block_number: BlockNumber) -> list[Allocator]:
    """
    Fetch allocators at the given block and return them as a list of Allocator objects.
    Filter records to include only those with mintedOsTokenShares > 0.
    """
    query = gql(
        """
        query getAllocators($block: Int, $first: Int, $lastID: String){
          allocators(
           block: {number: $block},
            where: {
                id_gt: $lastID
            },
            orderBy: id
            first: $first
          ){
          vault {
            id
          }
          id
          address
          shares
          assets
          mintedOsTokenShares
          }
        }
        """
    )
    params = {
        'block': block_number,
    }
    response = await graph_client.fetch_pages(query, params=params, cursor_pagination=True)
    tmp_allocators: defaultdict[str, dict[str, Wei]] = defaultdict(dict)
    allocators: list[Allocator] = []
    for item in response:
        if int(item['mintedOsTokenShares']) > 0:
            tmp_allocators[item['address']][item['vault']['id']] = Wei(
                int(item['mintedOsTokenShares'])
            )
    for allocator_address, vaults in tmp_allocators.items():
        vault_shares = [
            VaultShares(address=Web3.to_checksum_address(vault_address), minted_shares=shares)
            for vault_address, shares in vaults.items()
        ]
        allocators.append(
            Allocator(
                address=Web3.to_checksum_address(allocator_address), vault_shares=vault_shares
            )
        )
    return allocators


async def graph_get_leverage_positions(block_number: BlockNumber) -> list[LeverageStrategyPosition]:
    query = gql(
        """
        query PositionsQuery($block: Int,  $first: Int, $skip: Int) {
          leverageStrategyPositions(
            block: { number: $block },
            orderBy: borrowLtv,
            orderDirection: desc,
            first: $first
            skip: $skip
          ) {
            user
            proxy
            vault {
              id
            }
            osTokenShares
            assets
          }
        }
        """
    )
    params = {'block': block_number}
    response = await graph_client.fetch_pages(query, params=params)
    return [LeverageStrategyPosition.from_graph(item) for item in response]
