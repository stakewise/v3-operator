from dataclasses import asdict, dataclass

from ens.constants import EMPTY_ADDR_HEX
from eth_typing import BlockNumber, ChecksumAddress
from sw_utils.networks import CHIADO, GNOSIS, HOODI, MAINNET
from sw_utils.networks import NETWORKS as BASE_NETWORKS
from sw_utils.networks import BaseNetworkConfig
from web3 import Web3
from web3.types import Gwei, Wei

AVAILABLE_NETWORKS = [MAINNET, HOODI, GNOSIS, CHIADO]
RATED_NETWORKS = [MAINNET]


@dataclass
# pylint: disable-next=too-many-instance-attributes
class NetworkConfig(BaseNetworkConfig):
    WALLET_BALANCE_SYMBOL: str
    VAULT_BALANCE_SYMBOL: str
    DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress
    V2_POOL_ESCROW_CONTRACT_ADDRESS: ChecksumAddress
    HOT_WALLET_MIN_BALANCE: Wei
    STAKEWISE_API_URL: str
    RATED_API_URL: str
    CONFIG_UPDATE_EVENT_BLOCK: BlockNumber
    DEFAULT_DVT_RELAYER_ENDPOINT: str
    MAX_FEE_PER_GAS_GWEI: Gwei

    @property
    def IS_SUPPORT_V2_MIGRATION(self) -> bool:
        """Check if network support for v2-to-v3 protocol migration"""
        return Web3.to_checksum_address(EMPTY_ADDR_HEX) not in [
            self.V2_POOL_CONTRACT_ADDRESS,
            self.V2_POOL_ESCROW_CONTRACT_ADDRESS,
            self.GENESIS_VAULT_CONTRACT_ADDRESS,
        ]


NETWORKS: dict[str, NetworkConfig] = {
    MAINNET: NetworkConfig(
        **asdict(BASE_NETWORKS[MAINNET]),
        WALLET_BALANCE_SYMBOL='ETH',
        VAULT_BALANCE_SYMBOL='ETH',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x75AB6DdCe07556639333d3Df1eaa684F5735223e'
        ),
        V2_POOL_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x2296e122c1a20Fca3CAc3371357BdAd3be0dF079'
        ),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.03', 'ether'),
        STAKEWISE_API_URL='https://mainnet-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(21471524),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://mainnet-dvt-relayer.stakewise.io',
        MAX_FEE_PER_GAS_GWEI=Gwei(10),
    ),
    HOODI: NetworkConfig(
        **asdict(BASE_NETWORKS[HOODI]),
        WALLET_BALANCE_SYMBOL='HoodiETH',
        VAULT_BALANCE_SYMBOL='HoodiETH',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x93a3f880E07B27dacA6Ef2d3C23E77DBd6294487'
        ),
        V2_POOL_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.03', 'ether'),
        STAKEWISE_API_URL='https://hoodi-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(94090),
        DEFAULT_DVT_RELAYER_ENDPOINT='https://hoodi-dvt-relayer.stakewise.io',
        MAX_FEE_PER_GAS_GWEI=Gwei(10),
    ),
    GNOSIS: NetworkConfig(
        **asdict(BASE_NETWORKS[GNOSIS]),
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x58e16621B5c0786D6667D2d54E28A20940269E16'
        ),
        V2_POOL_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xfc9B67b6034F6B306EA9Bd8Ec1baf3eFA2490394'
        ),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
        STAKEWISE_API_URL='https://gnosis-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(37640206),
        DEFAULT_DVT_RELAYER_ENDPOINT='gnosis-dvt-relayer.stakewise.io',
        MAX_FEE_PER_GAS_GWEI=Gwei(2),
    ),
    CHIADO: NetworkConfig(
        **asdict(BASE_NETWORKS[CHIADO]),
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xFAce8504462AEb9BB6ae7Ecb206BD7B1EdF7956D'
        ),
        V2_POOL_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x928F9a91E674C886Cae0c377670109aBeF7e19d6'
        ),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
        STAKEWISE_API_URL='https://chiado-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(12896244),
        DEFAULT_DVT_RELAYER_ENDPOINT='chiado-dvt-relayer.stakewise.io',
        MAX_FEE_PER_GAS_GWEI=Gwei(2),
    ),
}
