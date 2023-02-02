from dataclasses import dataclass
from decimal import Decimal

from ens.constants import EMPTY_ADDR_HEX
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils.typings import Bytes32
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
    ORACLES_CONTRACT_ADDRESS: ChecksumAddress
    ORACLES_GENESIS_BLOCK: BlockNumber
    GENESIS_VALIDATORS_ROOT: Bytes32
    SECONDS_PER_BLOCK: Decimal
    CONFIRMATION_BLOCKS: int
    GENESIS_FORK_VERSION: bytes
    IS_POA: bool
    OPERATOR_MIN_BALANCE_ETH: str | None = None


NETWORKS = {
    MAINNET: NetworkConfig(
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(11052983),
        # TODO: replace with real values once contracts deployed
        ORACLES_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        ORACLES_GENESIS_BLOCK=BlockNumber(0),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95')
            )
        ),
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
        ORACLES_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x7f6F787feC4735B914EE4836A78487F2bFA9e70B'
        ),
        ORACLES_GENESIS_BLOCK=BlockNumber(8398334),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb')
            )
        ),
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
        ORACLES_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        ORACLES_GENESIS_BLOCK=BlockNumber(0),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47')
            )
        ),
        SECONDS_PER_BLOCK=Decimal('6.8'),
        CONFIRMATION_BLOCKS=24,
        GENESIS_FORK_VERSION=bytes.fromhex('00000064'),
        IS_POA=False,
    ),
}
