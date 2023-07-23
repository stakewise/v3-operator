import logging

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.types import Wei

from src.common.clients import ipfs_fetch_client
from src.common.typings import HarvestParams

logger = logging.getLogger(__name__)


async def fetch_harvest_params(
    vault_address: ChecksumAddress, ipfs_hash: str, rewards_root: bytes
) -> HarvestParams | None:
    ipfs_data = await ipfs_fetch_client.fetch_json(ipfs_hash)
    for vault_data in ipfs_data['vaults']:
        if vault_address == Web3.to_checksum_address(vault_data['vault']):
            unlocked_mev_reward = Wei(vault_data['unlocked_mev_reward'])
            reward = Wei(
                vault_data['consensus_reward']
                + unlocked_mev_reward
                + vault_data.get('locked_mev_reward', 0)
            )
            return HarvestParams(
                rewards_root=rewards_root,
                reward=reward,
                unlocked_mev_reward=unlocked_mev_reward,
                proof=[Web3.to_bytes(hexstr=x) for x in vault_data['proof']],
            )

    return None
