import backoff
from eth_typing import BlockNumber
from web3 import Web3

from src.common.clients import ipfs_fetch_client
from src.config.settings import NETWORK_CONFIG
from src.validators.typings import DepositData

VAULT_GENESIS_BLOCK: BlockNumber = NETWORK_CONFIG.VAULT_GENESIS_BLOCK
GENESIS_FORK_VERSION: bytes = NETWORK_CONFIG.GENESIS_FORK_VERSION
BLS_PUBLIC_KEY_LENGTH = 48
BLS_SIGNATURE_LENGTH = 96


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def fetch_vault_deposit_data(ipfs_hash: str) -> list[DepositData]:
    """Fetches deposit data from the IPFS."""
    ipfs_data = await ipfs_fetch_client.fetch_bytes(ipfs_hash)
    deposit_data_length = BLS_PUBLIC_KEY_LENGTH + BLS_SIGNATURE_LENGTH

    result = []
    validator_index = 0
    for i in range(0, len(ipfs_data), deposit_data_length):
        public_key = ipfs_data[i: i + BLS_PUBLIC_KEY_LENGTH]
        signature = ipfs_data[i + BLS_PUBLIC_KEY_LENGTH: i + deposit_data_length]
        result.append(DepositData(
            validator_index=validator_index,
            public_key=Web3.to_hex(public_key),
            signature=Web3.to_hex(signature)
        ))
        validator_index += 1

    return result
