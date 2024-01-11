import logging

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.types import Wei

from src.common.clients import ipfs_fetch_client
from src.common.contracts import vault_contract
from src.common.typings import HarvestParams
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def fetch_harvest_params(
    vault_address: ChecksumAddress, ipfs_hash: str, rewards_root: bytes
) -> HarvestParams | None:
    ipfs_data = await ipfs_fetch_client.fetch_json(ipfs_hash)
    mev_escrow = await vault_contract.mev_escrow()

    for vault_data in ipfs_data['vaults']:  # type: ignore
        if vault_address != Web3.to_checksum_address(vault_data['vault']):
            continue

        if mev_escrow == settings.network_config.SHARED_MEV_ESCROW_CONTRACT_ADDRESS:
            # shared mev vault
            unlocked_mev_reward = Wei(vault_data['unlocked_mev_reward'])
            reward = Wei(
                vault_data['consensus_reward']
                + unlocked_mev_reward
                + vault_data['locked_mev_reward']
            )
        else:
            # own mev vault
            unlocked_mev_reward = Wei(0)
            reward = Wei(vault_data['consensus_reward'])

        return HarvestParams(
            rewards_root=rewards_root,
            reward=reward,
            unlocked_mev_reward=unlocked_mev_reward,
            proof=[Web3.to_bytes(hexstr=x) for x in vault_data['proof']],
        )

    return None
