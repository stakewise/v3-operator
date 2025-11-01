import logging
from collections import defaultdict

from eth_typing import ChecksumAddress
from gql import gql
from web3 import Web3

from src.common.clients import graph_client
from src.common.typings import ExitRequest
from src.meta_vault.typings import Vault

logger = logging.getLogger(__name__)


async def graph_get_vaults(
    vaults: list[ChecksumAddress] | None = None,
    is_meta_vault: bool | None = None,
) -> dict[ChecksumAddress, Vault]:
    """
    Returns mapping from vault address to Vault object
    """
    where_conditions: list[str] = []
    params: dict = {}

    if vaults == []:
        return {}

    if vaults:
        where_conditions.append('id_in: $vaults')
        params['vaults'] = [v.lower() for v in vaults]

    if is_meta_vault is not None:
        where_conditions.append('isMetaVault: $isMetaVault')
        params['isMetaVault'] = is_meta_vault

    where_conditions_str = '\n'.join(where_conditions)
    where_clause = f'where: {{ {where_conditions_str} }}' if where_conditions else ''

    filters = ['first: $first', 'skip: $skip']

    if where_clause:
        filters.append(where_clause)

    query = f"""
        query VaultQuery($first: Int, $skip: Int, $vaults: [String], $isMetaVault: Boolean) {{
            vaults(
                {', '.join(filters)}
            ) {{
                id
                isMetaVault
                subVaults {{
                    subVault
                }}
                canHarvest
                proof
                proofReward
                proofUnlockedMevReward
                rewardsRoot
            }}
        }}
        """

    response = await graph_client.fetch_pages(gql(query), params)

    graph_vaults_map: dict[ChecksumAddress, Vault] = {}

    for vault_item in response:
        vault = Vault.from_graph(vault_item)
        graph_vaults_map[vault.address] = vault

    return graph_vaults_map


async def graph_get_exit_requests_for_meta_vault(
    meta_vault: ChecksumAddress,
) -> dict[ChecksumAddress, list[ExitRequest]]:
    """
    Returns mapping from sub-vault address to list of ExitRequest objects
    Skips claimed exit requests and those with exitedAssets == 0
    """
    query = gql(
        """
        query exitRequestQuery($owner: String, $first: Int, $skip: Int) {
          exitRequests(
            where: { owner: $owner, isClaimed: false, exitedAssets_gt: 0 },
            orderBy: positionTicket,
            first: $first,
            skip: $skip
          ) {
            id
            positionTicket
            timestamp
            owner
            receiver
            exitQueueIndex
            isClaimed
            isClaimable
            exitedAssets
            totalAssets
            vault {
              id
            }
          }
        }
        """
    )
    params = {'owner': meta_vault.lower()}
    response = await graph_client.fetch_pages(query, params=params)
    result = defaultdict(list)

    for data in response:
        vault = Web3.to_checksum_address(data['vault']['id'])
        result[vault].append(ExitRequest.from_graph(data))

    return result
