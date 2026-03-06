from typing import cast

from hexbytes import HexBytes
from sw_utils.networks import GNO_NETWORKS
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, Wei

from src.common.clients import ipfs_fetch_client
from src.common.contracts import VaultContract, keeper_contract
from src.common.typings import HarvestParams
from src.config.settings import settings


async def get_harvest_params(
    vault: ChecksumAddress, block_number: BlockNumber | None = None
) -> HarvestParams | None:
    """Get harvest params for a single vault."""
    result = await get_multiple_harvest_params([vault], block_number)
    return result[vault]


async def get_multiple_harvest_params(
    vaults: list[ChecksumAddress], block_number: BlockNumber | None = None
) -> dict[ChecksumAddress, HarvestParams | None]:
    """Get harvest params for multiple vaults.

    IPFS data and last rewards are fetched once, then reused for all vaults.
    """
    results: dict[ChecksumAddress, HarvestParams | None] = {}
    if not vaults:
        return results

    last_rewards = await keeper_contract.get_last_rewards_update(block_number)
    if last_rewards is None:
        return {vault: None for vault in vaults}

    ipfs_data = await ipfs_fetch_client.fetch_json(last_rewards.ipfs_hash)

    for vault in vaults:
        if not await keeper_contract.can_harvest(vault, block_number):
            results[vault] = None
            continue

        vault_contract = VaultContract(vault)
        results[vault] = await _extract_harvest_params(
            vault_contract=vault_contract,
            ipfs_data=cast(dict, ipfs_data),
            rewards_root=last_rewards.rewards_root,
        )

    return results


async def _extract_harvest_params(
    vault_contract: VaultContract, ipfs_data: dict, rewards_root: bytes
) -> HarvestParams | None:
    """Extract harvest params for a single vault from pre-fetched IPFS data."""
    mev_escrow = await vault_contract.mev_escrow()

    for vault_data in ipfs_data['vaults']:
        if vault_contract.contract_address != Web3.to_checksum_address(vault_data['vault']):
            continue

        if mev_escrow == settings.network_config.SHARED_MEV_ESCROW_CONTRACT_ADDRESS:
            # shared mev vault
            if settings.network in GNO_NETWORKS:
                reward = vault_data['consensus_reward']
            else:
                reward = Wei(
                    vault_data['consensus_reward']
                    + vault_data['unlocked_mev_reward']
                    + vault_data['locked_mev_reward']
                )
            unlocked_mev_reward = Wei(vault_data['unlocked_mev_reward'])
        else:
            # own mev vault
            unlocked_mev_reward = Wei(0)
            reward = Wei(vault_data['consensus_reward'])

        return HarvestParams(
            rewards_root=HexBytes(rewards_root),
            reward=reward,
            unlocked_mev_reward=unlocked_mev_reward,
            proof=[HexBytes(Web3.to_bytes(hexstr=x)) for x in vault_data['proof']],
        )

    return None
