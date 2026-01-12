import logging

from eth_typing import BlockNumber
from gql import gql

from src.common.clients import graph_client
from src.redeem.typings import Allocator, LeverageStrategyPosition

logger = logging.getLogger(__name__)


async def graph_get_allocators(block_number: BlockNumber) -> list[Allocator]:
    """
    Returns mapping from sub-vault address to list of ExitRequest objects
    Skips claimed exit requests and those with exitedAssets == 0
    """
    query = gql(
        """
        query getAllocators($block: Int, $first: Int, $skip: Int){
          allocators(
           block: {number: $block},
            first: $first
            skip: $skip
          ){
          vault {
            id
          }
          id
          address
          mintedOsTokenShares
          }
        }
        """
    )
    params = {
        'block': block_number,
    }
    response = await graph_client.fetch_pages(query, params=params)
    return [Allocator.from_graph(item) for item in response]


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
