from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3 import Web3
from web3.types import Wei

from src.common.clients import ipfs_fetch_client
from src.common.contracts import keeper_contract, vault_contract
from src.common.typings import HarvestParams
from src.config.networks import GNOSIS_NETWORKS
from src.config.settings import settings


async def get_harvest_params() -> HarvestParams | None:
    last_rewards = await keeper_contract.get_last_rewards_update()
    if last_rewards is None:
        return None

    if not await keeper_contract.can_harvest(vault_contract.contract_address):
        return None

    harvest_params = await _fetch_harvest_params_from_ipfs(
        vault_address=settings.vault,
        ipfs_hash=last_rewards.ipfs_hash,
        rewards_root=last_rewards.rewards_root,
    )
    return harvest_params


async def _fetch_harvest_params_from_ipfs(
    vault_address: ChecksumAddress, ipfs_hash: str, rewards_root: bytes
) -> HarvestParams | None:
    ipfs_data = await ipfs_fetch_client.fetch_json(ipfs_hash)
    mev_escrow = await vault_contract.mev_escrow()

    for vault_data in ipfs_data['vaults']:  # type: ignore
        if vault_address != Web3.to_checksum_address(vault_data['vault']):
            continue

        if mev_escrow == settings.network_config.SHARED_MEV_ESCROW_CONTRACT_ADDRESS:
            # shared mev vault
            if settings.network in GNOSIS_NETWORKS:
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
