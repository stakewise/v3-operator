from dataclasses import dataclass

from ens.constants import EMPTY_ADDR_HEX
from eth_typing import ChecksumAddress
from web3 import Web3
from web3.types import Wei

MAINNET = "mainnet"
GOERLI = "goerli"
GNOSIS = "gnosis"


@dataclass
class NetworkConfig:
    SLOTS_PER_EPOCH: int
    SECONDS_PER_SLOT: int
    VAULT_CONTRACT_ADDRESS: ChecksumAddress
    ORACLE_CONTRACT_ADDRESS: ChecksumAddress
    DEPOSIT_CONTRACT_ADDRESS: ChecksumAddress
    DEPOSITS_GENESIS_BLOCK: int
    DEPOSIT_AMOUNT: Wei
    CONFIRMATION_BLOCKS: int
    CHAIN_ID: int
    IS_POA: bool


NETWORKS = {
    MAINNET: NetworkConfig(
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        # TODO: replace with real values once contracts deployed
        VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        ORACLE_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        DEPOSIT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            "0x00000000219ab540356cBB839Cbe05303d7705Fa"
        ),
        DEPOSITS_GENESIS_BLOCK=1,
        DEPOSIT_AMOUNT=Web3.to_wei(32, "ether"),
        CONFIRMATION_BLOCKS=15,
        CHAIN_ID=1,
        IS_POA=False,
    ),
    GOERLI: NetworkConfig(
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        # TODO: replace with real values once contracts deployed
        VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        ORACLE_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        DEPOSIT_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        DEPOSITS_GENESIS_BLOCK=1,
        DEPOSIT_AMOUNT=Web3.to_wei(32, "ether"),
        CONFIRMATION_BLOCKS=15,
        CHAIN_ID=1,
        IS_POA=True,
    ),
    GNOSIS: NetworkConfig(
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        # TODO: replace with real values once contracts deployed
        VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        ORACLE_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        DEPOSIT_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        DEPOSIT_AMOUNT=Web3.to_wei(1, "ether"),
        DEPOSITS_GENESIS_BLOCK=1,
        CONFIRMATION_BLOCKS=15,
        CHAIN_ID=1,
        IS_POA=True,
    ),
}
