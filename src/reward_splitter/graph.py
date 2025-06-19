from collections import defaultdict

from eth_typing import BlockNumber, ChecksumAddress
from gql import gql
from hexbytes import HexBytes
from web3 import Web3
from web3.types import Wei

from src.common.clients import graph_client
from src.reward_splitter.typings import (
    ExitRequest,
    RewardSplitter,
    RewardSplitterShareHolder,
    Vault,
)


async def graph_get_reward_splitters(
    block_number: BlockNumber, vaults: list[ChecksumAddress]
) -> list[RewardSplitter]:
    query = gql(
        '''
        query Query($block: Int, $first: Int, $skip: Int, $vaults: [String]) {
            rewardSplitters(
                block: {number: $block},
                where: {
                    vault_in: $vaults,
                    version_gte: 3,
                    isClaimOnBehalfEnabled: true
                }
            ) {
                id
                vault {
                    id
                }
                shareHolders(where: {earnedVaultAssets_gt: 0}) {
                    address
                    shares
                    earnedVaultAssets
                }
            }
        }
    '''
    )
    params = {
        'block': block_number,
        'vaults': [v.lower() for v in vaults],
    }
    response = await graph_client.fetch_pages(query, params=params)
    reward_splitters = []

    for reward_splitter_item in response:
        reward_splitter = RewardSplitter(
            address=Web3.to_checksum_address(reward_splitter_item['id']),
            vault=Web3.to_checksum_address(reward_splitter_item['vault']['id']),
            shareholders=[],
        )
        for shareholder_item in reward_splitter_item['shareHolders']:
            shareholder = RewardSplitterShareHolder(
                address=Web3.to_checksum_address(shareholder_item['address']),
                earned_vault_assets=Wei(int(shareholder_item['earnedVaultAssets'])),
            )
            reward_splitter.shareholders.append(shareholder)
        reward_splitters.append(reward_splitter)

    return reward_splitters


async def graph_get_claimable_exit_requests(
    block_number: BlockNumber, receivers: list[ChecksumAddress]
) -> dict[ChecksumAddress, list[ExitRequest]]:
    """
    Returns dict{receiver: list[ExitRequest]}
    """
    query = gql(
        '''
        query Query($block: Int, $first: Int, $skip: Int, $receivers: [String]) {
            exitRequests(
                block: {number: $block},
                where: {
                    receiver_in: $receivers,
                    isClaimable: true,
                    isClaimed: false
                }
            ) {
                id
                isClaimable
                isClaimed
                positionTicket
                timestamp
                exitQueueIndex
                receiver
                totalAssets
                exitedAssets
            }
        }
    '''
    )
    params = {
        'block': block_number,
        'receivers': [rs.lower() for rs in receivers],
    }
    response = await graph_client.fetch_pages(query, params=params)

    exit_requests: dict[ChecksumAddress, list[ExitRequest]] = defaultdict(list)

    for exit_request_item in response:
        exit_request = ExitRequest.from_graph(exit_request_item)
        if exit_request.can_be_claimed:
            exit_requests[exit_request.receiver].append(exit_request)

    return exit_requests


async def graph_get_vaults(vaults: list[ChecksumAddress]) -> dict[ChecksumAddress, Vault]:
    """
    Returns dict {vault_address: GraphVault}
    """
    query = gql(
        """
      query VaultQuery($vaults: [String]) {
        vaults(
          where: {
            id_in: $vaults
          }
        ) {
          id
          canHarvest
          proof
          proofReward
          proofUnlockedMevReward
          rewardsRoot
        }
      }
      """
    )
    params = {
        'vaults': [v.lower() for v in vaults],
    }

    response = await graph_client.run_query(query, params)
    vault_data = response['vaults']  # pylint: disable=unsubscriptable-object

    graph_vaults_map: dict[ChecksumAddress, Vault] = {}

    for vault_item in vault_data:
        vault_address = Web3.to_checksum_address(vault_item['id'])

        can_harvest = vault_item['canHarvest']
        rewards_root = HexBytes(Web3.to_bytes(hexstr=vault_item['rewardsRoot']))
        proof_reward = Wei(int(vault_item['proofReward']))
        proof_unlocked_mev_reward = Wei(int(vault_item['proofUnlockedMevReward']))
        proof = [HexBytes(Web3.to_bytes(hexstr=p)) for p in vault_item['proof']]

        graph_vaults_map[vault_address] = Vault(
            address=vault_address,
            can_harvest=can_harvest,
            rewards_root=rewards_root,
            proof_reward=proof_reward,
            proof_unlocked_mev_reward=proof_unlocked_mev_reward,
            proof=proof,
        )

    return graph_vaults_map
