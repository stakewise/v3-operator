import logging

from eth_typing import BlockNumber, ChecksumAddress
from gql import gql
from web3 import Web3

from src.common.clients import graph_client
from src.redeem.typings import Allocator

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


async def graph_get_leverage_positions_proxies(block_number: BlockNumber) -> list[ChecksumAddress]:
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
            proxy
          }
        }
        """
    )
    params = {'block': block_number}
    response = await graph_client.fetch_pages(query, params=params)
    return [Web3.to_checksum_address(item['proxy']) for item in response]
