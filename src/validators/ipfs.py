import logging

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.types import Wei

from src.common.clients import ipfs_fetch_client
from src.validators.typings import HarvestParams

logger = logging.getLogger(__name__)


async def fetch_harvest_params(
    vault_address: ChecksumAddress, ipfs_hash: str, rewards_root: bytes
) -> HarvestParams:
    ipfs_data = await ipfs_fetch_client.fetch_json(ipfs_hash)
    for vault_data in ipfs_data:
        if vault_address == Web3.to_checksum_address(vault_data['vault']):
            return HarvestParams(
                rewards_root=rewards_root,
                reward=Wei(vault_data['reward']),
                proof=[Web3.to_bytes(hexstr=x) for x in vault_data['proof']]
            )
    raise ValueError(f"Can't find vault {vault_address} in reward file {ipfs_hash}")
