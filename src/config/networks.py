from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import timedelta

from ens.constants import EMPTY_ADDR_HEX
from eth_typing import BlockNumber, ChecksumAddress
from sw_utils.networks import GNOSIS, HOODI, MAINNET
from sw_utils.networks import NETWORKS as BASE_NETWORKS
from sw_utils.networks import BaseNetworkConfig
from web3 import Web3
from web3.types import Gwei, Wei

AVAILABLE_NETWORKS = [MAINNET, HOODI, GNOSIS]
RATED_NETWORKS = [MAINNET]

ZERO_CHECKSUM_ADDRESS = Web3.to_checksum_address(EMPTY_ADDR_HEX)  # noqa: E501


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
    MAX_VALIDATOR_BALANCE_GWEI: Gwei
    SHARD_COMMITTEE_PERIOD: int
    PENDING_PARTIAL_WITHDRAWALS_LIMIT: int
    PENDING_CONSOLIDATIONS_LIMIT: int
    MAX_WITHDRAWAL_REQUESTS_PER_BLOCK: int
    EXCESS_EXECUTION_REQUESTS_STORAGE_SLOT: int
    EXECUTION_REQUEST_COUNT_STORAGE_SLOT: int
    MIN_EXECUTION_REQUEST_FEE: int
    EXECUTION_REQUEST_FEE_UPDATE_FRACTION: int
    EXECUTION_REQUEST_QUEUE_HEAD_STORAGE_SLOT: int
    EXECUTION_REQUEST_QUEUE_TAIL_STORAGE_SLOT: int
    EXECUTION_REQUEST_QUEUE_STORAGE_OFFSET: int
    TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK: int
    TARGET_CONSOLIDATION_REQUESTS_PER_BLOCK: int
    NODE_CONFIG: NodeConfig


@dataclass
class NodeConfig:
    CONSENSUS_CHECKPOINT_SYNC_URL: str
    ERA_URL: str
    MIN_MEMORY_GB: int
    MIN_DISK_SPACE_TB: float
    INITIAL_SYNC_STAGE_TO_ETA_TIMEDELTA: dict[str, timedelta]

    @property
    def INITIAL_SYNC_STAGE_TO_ETA(self) -> dict[str, int]:
        """
        Returns initial sync stage to ETA mapping in seconds.
        """
        return {
            stage: int(delta.total_seconds())
            for stage, delta in self.INITIAL_SYNC_STAGE_TO_ETA_TIMEDELTA.items()
        }

    @property
    def INITIAL_SYNC_ETA(self) -> int:
        """
        Returns the total initial sync ETA in seconds.
        """
        return sum(self.INITIAL_SYNC_STAGE_TO_ETA.values())


NETWORKS: dict[str, NetworkConfig] = {
    MAINNET: NetworkConfig(
        **asdict(BASE_NETWORKS[MAINNET]),
        WALLET_BALANCE_SYMBOL='ETH',
        VAULT_BALANCE_SYMBOL='ETH',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x75AB6DdCe07556639333d3Df1eaa684F5735223e'
        ),
        VALIDATORS_CHECKER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xA89629B41477560d49dd56ef1a59BD214362aCDC'
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
        MAX_VALIDATOR_BALANCE_GWEI=Gwei(int(Web3.from_wei(Web3.to_wei(1945, 'ether'), 'gwei'))),
        SHARD_COMMITTEE_PERIOD=256,  # epochs
        PENDING_PARTIAL_WITHDRAWALS_LIMIT=134217728,
        PENDING_CONSOLIDATIONS_LIMIT=262144,
        MAX_WITHDRAWAL_REQUESTS_PER_BLOCK=16,
        EXCESS_EXECUTION_REQUESTS_STORAGE_SLOT=0,
        EXECUTION_REQUEST_COUNT_STORAGE_SLOT=1,
        MIN_EXECUTION_REQUEST_FEE=1,
        EXECUTION_REQUEST_FEE_UPDATE_FRACTION=17,
        EXECUTION_REQUEST_QUEUE_HEAD_STORAGE_SLOT=2,
        EXECUTION_REQUEST_QUEUE_TAIL_STORAGE_SLOT=3,
        EXECUTION_REQUEST_QUEUE_STORAGE_OFFSET=4,
        TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK=2,
        TARGET_CONSOLIDATION_REQUESTS_PER_BLOCK=1,
        NODE_CONFIG=NodeConfig(
            CONSENSUS_CHECKPOINT_SYNC_URL='https://beaconstate.ethstaker.cc/',
            ERA_URL='https://data.ethpandaops.io/era1/mainnet/',
            MIN_MEMORY_GB=16,
            MIN_DISK_SPACE_TB=2,
            INITIAL_SYNC_STAGE_TO_ETA_TIMEDELTA={
                'Execution': timedelta(hours=46),
                'StorageHashing': timedelta(hours=1),
                'MerkleExecute': timedelta(hours=1),
            },
        ),
    ),
    HOODI: NetworkConfig(
        **asdict(BASE_NETWORKS[HOODI]),
        WALLET_BALANCE_SYMBOL='HoodiETH',
        VAULT_BALANCE_SYMBOL='HoodiETH',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x93a3f880E07B27dacA6Ef2d3C23E77DBd6294487'
        ),
        VALIDATORS_CHECKER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xA89629B41477560d49dd56ef1a59BD214362aCDC'
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
        MAX_VALIDATOR_BALANCE_GWEI=Gwei(int(Web3.from_wei(Web3.to_wei(1945, 'ether'), 'gwei'))),
        SHARD_COMMITTEE_PERIOD=256,  # epochs
        PENDING_PARTIAL_WITHDRAWALS_LIMIT=134217728,
        PENDING_CONSOLIDATIONS_LIMIT=262144,
        MAX_WITHDRAWAL_REQUESTS_PER_BLOCK=16,
        EXCESS_EXECUTION_REQUESTS_STORAGE_SLOT=0,
        EXECUTION_REQUEST_COUNT_STORAGE_SLOT=1,
        MIN_EXECUTION_REQUEST_FEE=1,
        EXECUTION_REQUEST_FEE_UPDATE_FRACTION=17,
        EXECUTION_REQUEST_QUEUE_HEAD_STORAGE_SLOT=2,
        EXECUTION_REQUEST_QUEUE_TAIL_STORAGE_SLOT=3,
        EXECUTION_REQUEST_QUEUE_STORAGE_OFFSET=4,
        TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK=2,
        TARGET_CONSOLIDATION_REQUESTS_PER_BLOCK=1,
        NODE_CONFIG=NodeConfig(
            CONSENSUS_CHECKPOINT_SYNC_URL='https://hoodi.beaconstate.ethstaker.cc/',
            ERA_URL='',
            MIN_MEMORY_GB=16,
            MIN_DISK_SPACE_TB=0.1,  # 100 GB
            INITIAL_SYNC_STAGE_TO_ETA_TIMEDELTA={
                'Execution': timedelta(hours=7),
                'StorageHashing': timedelta(minutes=30),
                'MerkleExecute': timedelta(minutes=30),
            },
        ),
    ),
    GNOSIS: NetworkConfig(
        **asdict(BASE_NETWORKS[GNOSIS]),
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x58e16621B5c0786D6667D2d54E28A20940269E16'
        ),
        VALIDATORS_CHECKER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xA89629B41477560d49dd56ef1a59BD214362aCDC'
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
        MAX_VALIDATOR_BALANCE_GWEI=Gwei(int(Web3.from_wei(Web3.to_wei(1800, 'ether'), 'gwei'))),
        SHARD_COMMITTEE_PERIOD=256,  # epochs
        PENDING_PARTIAL_WITHDRAWALS_LIMIT=134217728,
        PENDING_CONSOLIDATIONS_LIMIT=262144,
        MAX_WITHDRAWAL_REQUESTS_PER_BLOCK=16,
        EXCESS_EXECUTION_REQUESTS_STORAGE_SLOT=0,
        EXECUTION_REQUEST_COUNT_STORAGE_SLOT=1,
        MIN_EXECUTION_REQUEST_FEE=1,
        EXECUTION_REQUEST_FEE_UPDATE_FRACTION=17,
        EXECUTION_REQUEST_QUEUE_HEAD_STORAGE_SLOT=2,
        EXECUTION_REQUEST_QUEUE_TAIL_STORAGE_SLOT=3,
        EXECUTION_REQUEST_QUEUE_STORAGE_OFFSET=4,
        TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK=2,
        TARGET_CONSOLIDATION_REQUESTS_PER_BLOCK=1,
        NODE_CONFIG=NodeConfig(
            CONSENSUS_CHECKPOINT_SYNC_URL='https://beacon.gnosischain.com/',
            ERA_URL='',
            MIN_MEMORY_GB=16,
            MIN_DISK_SPACE_TB=2,
            INITIAL_SYNC_STAGE_TO_ETA_TIMEDELTA={
                'Execution': timedelta(hours=46),
                'StorageHashing': timedelta(hours=1),
                'MerkleExecute': timedelta(hours=1),
            },
        ),
    ),
}
