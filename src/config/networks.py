from dataclasses import dataclass
from decimal import Decimal

from ens.constants import EMPTY_ADDR_HEX
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import Wei

MAINNET = 'mainnet'
GOERLI = 'goerli'
GNOSIS = 'gnosis'

ETH_NETWORKS = [MAINNET, GOERLI]
GNO_NETWORKS = [GNOSIS]


@dataclass
# pylint: disable-next=too-many-instance-attributes
class NetworkConfig:
    SYMBOL: str
    VALIDATORS_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress  # consensus deposit contract
    VALIDATORS_REGISTRY_GENESIS_BLOCK: BlockNumber  # consensus deposit contract genesis
    KEEPER_CONTRACT_ADDRESS: ChecksumAddress
    KEEPER_GENESIS_BLOCK: BlockNumber
    GENESIS_VALIDATORS_ROOT: Bytes32
    GENESIS_VALIDATORS_IPFS_HASH: str
    SLOTS_PER_EPOCH: int
    SECONDS_PER_BLOCK: Decimal
    GENESIS_FORK_VERSION: bytes
    IS_POA: bool
    HOT_WALLET_MIN_BALANCE: Wei


NETWORKS = {
    MAINNET: NetworkConfig(
        SYMBOL='ETH',
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(11052983),
        # TODO: replace with real values once contracts deployed
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        KEEPER_GENESIS_BLOCK=BlockNumber(0),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95')
            )
        ),
        GENESIS_VALIDATORS_IPFS_HASH='',
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_BLOCK=Decimal(12),
        GENESIS_FORK_VERSION=bytes.fromhex('00000000'),
        IS_POA=False,
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
    ),
    GOERLI: NetworkConfig(
        SYMBOL='GoerliETH',
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xff50ed3d0ec03aC01D4C79aAd74928BFF48a7b2b'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(4367321),
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x893ceb1cF23475defE3747670EbE4b40e629c6fD'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(9583358),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb')
            )
        ),
        GENESIS_VALIDATORS_IPFS_HASH='QmQo3oLYxqWm75fbgJJkCaUttZoYVqZhZj9r99r1UsZVpu',
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_BLOCK=Decimal(12),
        GENESIS_FORK_VERSION=bytes.fromhex('00001020'),
        IS_POA=True,
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
    ),
    GNOSIS: NetworkConfig(
        SYMBOL='xDAI',
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x0B98057eA310F4d31F2a452B414647007d1645d9'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(19469076),
        # TODO: replace with real values once contracts deployed
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        KEEPER_GENESIS_BLOCK=BlockNumber(0),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47')
            )
        ),
        GENESIS_VALIDATORS_IPFS_HASH='',
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_BLOCK=Decimal('6.8'),
        GENESIS_FORK_VERSION=bytes.fromhex('00000064'),
        IS_POA=False,
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
    ),
}
