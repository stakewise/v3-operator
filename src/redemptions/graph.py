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
          mintedOsTokenShares
          ltv
          }
        }
        """
    )
    params = {
        'block': block_number,
    }
    response = await graph_client.fetch_pages(query, params=params, cursor_pagination=True)
    tmp_allocators: defaultdict[str, dict[str, tuple[Wei, float]]] = defaultdict(dict)
    allocators: list[Allocator] = []
    for item in response:
        if int(item['mintedOsTokenShares']) > 0:
            tmp_allocators[item['address']][item['vault']['id']] = (
                Wei(int(item['mintedOsTokenShares'])),
                float(item['ltv']),
            )
    for allocator_address, vaults in tmp_allocators.items():
        vault_shares = [
            VaultOsTokenPosition(
                address=Web3.to_checksum_address(vault_address),
                minted_shares=minted_shares,
                ltv=ltv,
            )
            for vault_address, (minted_shares, ltv) in vaults.items()
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
