from dataclasses import dataclass

from ens.constants import EMPTY_ADDR_HEX
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils.typings import Bytes32, ConsensusFork
from web3 import Web3
from web3.types import Wei

MAINNET = 'mainnet'
GNOSIS = 'gnosis'
HOLESKY = 'holesky'
CHIADO = 'chiado'

AVAILABLE_NETWORKS = [MAINNET, HOLESKY, GNOSIS, CHIADO]
GNOSIS_NETWORKS = [GNOSIS, CHIADO]
RATED_NETWORKS = [MAINNET, HOLESKY]


@dataclass
# pylint: disable-next=too-many-instance-attributes
class NetworkConfig:
    CHAIN_ID: int
    WALLET_BALANCE_SYMBOL: str
    VAULT_BALANCE_SYMBOL: str
    VALIDATORS_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress  # consensus deposit contract
    VALIDATORS_REGISTRY_GENESIS_BLOCK: BlockNumber  # consensus deposit contract genesis
    KEEPER_CONTRACT_ADDRESS: ChecksumAddress
    KEEPER_GENESIS_BLOCK: BlockNumber
    DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress
    V2_POOL_CONTRACT_ADDRESS: ChecksumAddress
    V2_POOL_GENESIS_BLOCK: BlockNumber
    V2_POOL_ESCROW_CONTRACT_ADDRESS: ChecksumAddress
    GENESIS_VAULT_CONTRACT_ADDRESS: ChecksumAddress
    GENESIS_VALIDATORS_ROOT: Bytes32
    GENESIS_VALIDATORS_IPFS_HASH: str
    SLOTS_PER_EPOCH: int
    SECONDS_PER_BLOCK: int
    GENESIS_FORK_VERSION: bytes
    HOT_WALLET_MIN_BALANCE: Wei
    SHAPELLA_FORK_VERSION: bytes
    SHAPELLA_EPOCH: int
    MULTICALL_CONTRACT_ADDRESS: ChecksumAddress
    SHARED_MEV_ESCROW_CONTRACT_ADDRESS: ChecksumAddress
    STAKEWISE_API_URL: str
    RATED_API_URL: str
    CONFIG_UPDATE_EVENT_BLOCK: BlockNumber

    @property
    def SHAPELLA_FORK(self) -> ConsensusFork:
        return ConsensusFork(
            version=self.SHAPELLA_FORK_VERSION,
            epoch=self.SHAPELLA_EPOCH,
        )

    @property
    def IS_SUPPORT_V2_MIGRATION(self) -> bool:
        """Check if network support for v2-to-v3 protocol migration"""
        return Web3.to_checksum_address(EMPTY_ADDR_HEX) not in [
            self.V2_POOL_CONTRACT_ADDRESS,
            self.V2_POOL_ESCROW_CONTRACT_ADDRESS,
            self.GENESIS_VAULT_CONTRACT_ADDRESS,
        ]


NETWORKS = {
    MAINNET: NetworkConfig(
        CHAIN_ID=1,
        WALLET_BALANCE_SYMBOL='ETH',
        VAULT_BALANCE_SYMBOL='ETH',
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(11052983),
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x6B5815467da09DaA7DC83Db21c9239d98Bb487b5'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(18470089),
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x75AB6DdCe07556639333d3Df1eaa684F5735223e'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xC874b064f465bdD6411D45734b56fac750Cda29A'
        ),
        V2_POOL_GENESIS_BLOCK=BlockNumber(11726297),
        V2_POOL_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x2296e122c1a20Fca3CAc3371357BdAd3be0dF079'
        ),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xAC0F906E433d58FA868F936E8A43230473652885'
        ),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95')
            )
        ),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeigzq2ntq5zw4tdym5vckbf66mla5q3ge2fzdgqslhckdytlmm7k7y',
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_BLOCK=12,
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x00000000')),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.03', 'ether'),
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x03000000')),
        SHAPELLA_EPOCH=194048,
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x48319f97E5Da1233c21c48b80097c0FB7a20Ff86'
        ),
        STAKEWISE_API_URL='https://mainnet-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(18470104),
    ),
    HOLESKY: NetworkConfig(
        CHAIN_ID=17000,
        WALLET_BALANCE_SYMBOL='HolETH',
        VAULT_BALANCE_SYMBOL='HolETH',
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x4242424242424242424242424242424242424242'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(0),
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xB580799Bf7d62721D1a523f0FDF2f5Ed7BA4e259'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(215379),
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xAC0F906E433d58FA868F936E8A43230473652885'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        V2_POOL_GENESIS_BLOCK=BlockNumber(0),
        V2_POOL_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xA9f21D016E2846BC9Be972Cf45d9e410283c971e'
        ),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x8A94e1d22D83990205843cda08376d16F150c9bb'
        ),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1')
            )
        ),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeihhaxvlkbvwda6jy3ucawb4cdmgbaumbvoi337gdyp6hdtlrfnb64',
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_BLOCK=12,
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x01017000')),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.03', 'ether'),
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x04017000')),
        SHAPELLA_EPOCH=256,
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xc98F25BcAA6B812a07460f18da77AF8385be7b56'
        ),
        STAKEWISE_API_URL='https://holesky-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(215397),
    ),
    GNOSIS: NetworkConfig(
        CHAIN_ID=100,
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x0B98057eA310F4d31F2a452B414647007d1645d9'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(19469076),
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcAC0e3E35d3BA271cd2aaBE688ac9DB1898C26aa'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(34778552),
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x58e16621B5c0786D6667D2d54E28A20940269E16'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x2f99472b727e15EECf9B9eFF9F7481B85d3b4444'
        ),
        V2_POOL_GENESIS_BLOCK=BlockNumber(21275812),
        V2_POOL_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xfc9B67b6034F6B306EA9Bd8Ec1baf3eFA2490394'
        ),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x4b4406Ed8659D03423490D8b62a1639206dA0A7a'
        ),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47')
            )
        ),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeid4xnpjblh4izjb32qygdubyugotivm5rscx6b3jpsez4vxlyig44',
        SLOTS_PER_EPOCH=16,
        SECONDS_PER_BLOCK=5,
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x00000064')),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x03000064')),
        SHAPELLA_EPOCH=648704,
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x30db0d10d3774e78f8cB214b9e8B72D4B402488a'
        ),
        STAKEWISE_API_URL='https://gnosis-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(34778569),
    ),
    CHIADO: NetworkConfig(
        CHAIN_ID=10200,
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xb97036A26259B7147018913bD58a774cf91acf25'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(155434),
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x5f31eD13eBF81B67a9f9498F3d1D2Da553058988'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(10627588),
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xFAce8504462AEb9BB6ae7Ecb206BD7B1EdF7956D'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        V2_POOL_GENESIS_BLOCK=BlockNumber(0),
        V2_POOL_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x928F9a91E674C886Cae0c377670109aBeF7e19d6'
        ),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xF82f6E46d0d0a9536b9CA4bc480372EeaFcd9E6c'
        ),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e')
            )
        ),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeih2he7opyg4e7ontq4cvh42tou4ekizpbn4emg6u5lhfziyxcm3zq',
        SLOTS_PER_EPOCH=16,
        SECONDS_PER_BLOCK=5,
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x0000006f')),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x0300006f')),
        SHAPELLA_EPOCH=244224,
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x453056f0bc4631abB15eEC656139f88067668E3E'
        ),
        STAKEWISE_API_URL='https://chiado-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(10627606),
    ),
}
