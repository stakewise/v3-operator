from dataclasses import dataclass
from decimal import Decimal

from eth_typing import BlockNumber, ChecksumAddress
from web3 import Web3

MAINNET = 'mainnet'
GOERLI = 'goerli'
GNOSIS = 'gnosis'

ETH_NETWORKS = [MAINNET, GOERLI]
GNO_NETWORKS = [GNOSIS]


@dataclass
class NetworkConfig:
    VALIDATORS_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress
    VALIDATORS_REGISTRY_GENESIS_BLOCK: BlockNumber
    VAULT_GENESIS_BLOCK: BlockNumber
    SECONDS_PER_BLOCK: Decimal
    CONFIRMATION_BLOCKS: int
    GENESIS_FORK_VERSION: bytes
    IS_POA: bool


NETWORKS = {
    MAINNET: NetworkConfig(
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(11052983),
        # TODO: replace with real values once contracts deployed
        VAULT_GENESIS_BLOCK=BlockNumber(0),
        SECONDS_PER_BLOCK=Decimal(12),
        CONFIRMATION_BLOCKS=64,
        GENESIS_FORK_VERSION=bytes.fromhex('00000000'),
        IS_POA=False,
    ),
    GOERLI: NetworkConfig(
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(4367321),
        # TODO: replace with real values once contracts deployed
        VAULT_GENESIS_BLOCK=BlockNumber(0),
        SECONDS_PER_BLOCK=Decimal(12),
        CONFIRMATION_BLOCKS=64,
        GENESIS_FORK_VERSION=bytes.fromhex('00001020'),
        IS_POA=True,
    ),
    GNOSIS: NetworkConfig(
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x0B98057eA310F4d31F2a452B414647007d1645d9'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(19469076),
        # TODO: replace with real values once contracts deployed
        VAULT_GENESIS_BLOCK=BlockNumber(0),
        SECONDS_PER_BLOCK=Decimal('6.8'),
        CONFIRMATION_BLOCKS=24,
        GENESIS_FORK_VERSION=bytes.fromhex('00000064'),
        IS_POA=False,
    ),
}
