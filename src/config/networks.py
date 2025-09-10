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

ZERO_CHECKSUM_ADDRESS = Web3.to_checksum_address(EMPTY_ADDR_HEX)  # noqa


@dataclass
# pylint: disable-next=too-many-instance-attributes
class NetworkConfig(BaseNetworkConfig):
    WALLET_BALANCE_SYMBOL: str
    VAULT_BALANCE_SYMBOL: str
    DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress
    VALIDATORS_CHECKER_CONTRACT_ADDRESS: ChecksumAddress
    CONSOLIDATION_CONTRACT_ADDRESS: ChecksumAddress
    WITHDRAWAL_CONTRACT_ADDRESS: ChecksumAddress
    WALLET_MIN_BALANCE: Wei
    STAKEWISE_API_URL: str
    STAKEWISE_GRAPH_ENDPOINT: str
    RATED_API_URL: str
    CONFIG_UPDATE_EVENT_BLOCK: BlockNumber
    MAX_FEE_PER_GAS_GWEI: Gwei
    SHARD_COMMITTEE_PERIOD: int
    PENDING_PARTIAL_WITHDRAWALS_LIMIT: int
    PENDING_CONSOLIDATIONS_LIMIT: int
    MAX_WITHDRAWAL_REQUESTS_PER_BLOCK: int


NETWORKS: dict[str, NetworkConfig] = {
    MAINNET: NetworkConfig(
        **asdict(BASE_NETWORKS[MAINNET]),
        WALLET_BALANCE_SYMBOL='ETH',
        VAULT_BALANCE_SYMBOL='ETH',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x75AB6DdCe07556639333d3Df1eaa684F5735223e'
        ),
        VALIDATORS_CHECKER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x5D075B63291b8A28f911b7535C7AE848283A72aB'
        ),
        CONSOLIDATION_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x0000BBdDc7CE488642fb579F8B00f3a590007251'
        ),
        WITHDRAWAL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000961Ef480Eb55e80D19ad83579A64c007002'
        ),
        WALLET_MIN_BALANCE=Web3.to_wei('0.03', 'ether'),
        STAKEWISE_API_URL='https://mainnet-api.stakewise.io/graphql',
        STAKEWISE_GRAPH_ENDPOINT=(
            'https://graphs.stakewise.io/mainnet/subgraphs/name/stakewise/prod'
        ),
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(21471524),
        MAX_FEE_PER_GAS_GWEI=Gwei(10),
        SHARD_COMMITTEE_PERIOD=256,  # epochs
        PENDING_PARTIAL_WITHDRAWALS_LIMIT=134217728,
        PENDING_CONSOLIDATIONS_LIMIT=262144,
        MAX_WITHDRAWAL_REQUESTS_PER_BLOCK=16,
    ),
    HOODI: NetworkConfig(
        **asdict(BASE_NETWORKS[HOODI]),
        WALLET_BALANCE_SYMBOL='HoodiETH',
        VAULT_BALANCE_SYMBOL='HoodiETH',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x93a3f880E07B27dacA6Ef2d3C23E77DBd6294487'
        ),
        VALIDATORS_CHECKER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x5D075B63291b8A28f911b7535C7AE848283A72aB'
        ),
        CONSOLIDATION_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x0000BBdDc7CE488642fb579F8B00f3a590007251'
        ),
        WITHDRAWAL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000961Ef480Eb55e80D19ad83579A64c007002'
        ),
        WALLET_MIN_BALANCE=Web3.to_wei('0.03', 'ether'),
        STAKEWISE_API_URL='https://hoodi-api.stakewise.io/graphql',
        STAKEWISE_GRAPH_ENDPOINT='https://graphs.stakewise.io/hoodi/subgraphs/name/stakewise/prod',
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(94090),
        MAX_FEE_PER_GAS_GWEI=Gwei(10),
        SHARD_COMMITTEE_PERIOD=256,  # epochs
        PENDING_PARTIAL_WITHDRAWALS_LIMIT=134217728,
        PENDING_CONSOLIDATIONS_LIMIT=262144,
        MAX_WITHDRAWAL_REQUESTS_PER_BLOCK=16,
    ),
    GNOSIS: NetworkConfig(
        **asdict(BASE_NETWORKS[GNOSIS]),
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x58e16621B5c0786D6667D2d54E28A20940269E16'
        ),
        VALIDATORS_CHECKER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x5D075B63291b8A28f911b7535C7AE848283A72aB'
        ),
        CONSOLIDATION_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x0000BBdDc7CE488642fb579F8B00f3a590007251'
        ),
        WITHDRAWAL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000961Ef480Eb55e80D19ad83579A64c007002'
        ),
        WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
        STAKEWISE_API_URL='https://gnosis-api.stakewise.io/graphql',
        STAKEWISE_GRAPH_ENDPOINT=(
            'https://graphs.stakewise.io/gnosis/subgraphs/name/stakewise/prod'
        ),
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(37640206),
        MAX_FEE_PER_GAS_GWEI=Gwei(2),
        SHARD_COMMITTEE_PERIOD=256,  # epochs
        PENDING_PARTIAL_WITHDRAWALS_LIMIT=134217728,
        PENDING_CONSOLIDATIONS_LIMIT=262144,
        MAX_WITHDRAWAL_REQUESTS_PER_BLOCK=16,
    ),
    CHIADO: NetworkConfig(
        **asdict(BASE_NETWORKS[CHIADO]),
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xFAce8504462AEb9BB6ae7Ecb206BD7B1EdF7956D'
        ),
        VALIDATORS_CHECKER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x5D075B63291b8A28f911b7535C7AE848283A72aB'
        ),
        CONSOLIDATION_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x0000BBdDc7CE488642fb579F8B00f3a590007251'
        ),
        WITHDRAWAL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000961Ef480Eb55e80D19ad83579A64c007002'
        ),
        WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
        STAKEWISE_API_URL='https://chiado-api.stakewise.io/graphql',
        STAKEWISE_GRAPH_ENDPOINT=(
            'https://graphs.stakewise.io/chiado/subgraphs/name/stakewise/prod'
        ),
        RATED_API_URL='https://api.rated.network',
        CONFIG_UPDATE_EVENT_BLOCK=BlockNumber(12896244),
        MAX_FEE_PER_GAS_GWEI=Gwei(2),
        SHARD_COMMITTEE_PERIOD=256,  # epochs
        PENDING_PARTIAL_WITHDRAWALS_LIMIT=134217728,
        PENDING_CONSOLIDATIONS_LIMIT=262144,
        MAX_WITHDRAWAL_REQUESTS_PER_BLOCK=16,
    ),
}
