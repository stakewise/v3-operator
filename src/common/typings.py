from dataclasses import dataclass
from enum import Enum

from hexbytes import HexBytes
from web3 import Web3
from web3.types import ChecksumAddress, Gwei, Wei


@dataclass
class RewardVoteInfo:
    rewards_root: bytes
    ipfs_hash: str


@dataclass
class HarvestParams:
    rewards_root: HexBytes
    reward: Wei
    unlocked_mev_reward: Wei
    proof: list[HexBytes]


@dataclass
class OracleApproval:
    signature: bytes
    ipfs_hash: str
    deadline: int


@dataclass
class OraclesApproval:
    signatures: bytes
    ipfs_hash: str
    deadline: int


@dataclass
class ExitQueueMissingAssetsParams:
    vault: ChecksumAddress
    withdrawing_assets: Wei
    exit_queue_cumulative_ticket: int


@dataclass
class PendingConsolidation:
    source_index: int
    target_index: int


@dataclass
class PendingPartialWithdrawal:
    validator_index: int
    amount: Gwei


class ValidatorType(Enum):
    V1 = '0x01'
    V2 = '0x02'


class ValidatorsRegistrationMode(Enum):
    """
    AUTO mode: validators are registered automatically when vault assets are enough.
    API mode: validators registration is triggered by API request.
    """

    AUTO = 'AUTO'
    API = 'API'


@dataclass
# pylint: disable-next=too-many-instance-attributes
class ExitRequest:
    id: str
    vault: ChecksumAddress
    position_ticket: int
    timestamp: int
    exit_queue_index: int | None
    is_claimed: bool
    is_claimable: bool
    receiver: ChecksumAddress
    exited_assets: Wei
    total_assets: Wei

    @property
    def can_be_claimed(self) -> bool:
        return self.is_claimable and self.exited_assets == self.total_assets

    @property
    def is_waiting_for_claim_delay(self) -> bool:
        """
        Returns True if the assets have exited (fully or partially),
        but the claim delay has not passed yet.
        Relevant for testnets with short exit queues
        """
        return self.has_exit_queue_index and not self.is_claimable and not self.is_claimed

    @property
    def has_exit_queue_index(self) -> bool:
        """Missing exit queue index may equal to None or -1"""
        return self.exit_queue_index is not None and self.exit_queue_index >= 0

    @staticmethod
    def from_graph(data: dict) -> 'ExitRequest':
        exit_queue_index = (
            int(data['exitQueueIndex']) if data.get('exitQueueIndex') is not None else None
        )
        return ExitRequest(
            id=data['id'],
            vault=Web3.to_checksum_address(data['vault']['id']),
            position_ticket=int(data['positionTicket']),
            timestamp=int(data['timestamp']),
            exit_queue_index=exit_queue_index,
            is_claimed=data['isClaimed'],
            is_claimable=data['isClaimable'],
            receiver=Web3.to_checksum_address(data['receiver']),
            exited_assets=Wei(int(data['exitedAssets'])),
            total_assets=Wei(int(data['totalAssets'])),
        )


class Singleton(type):
    _instances: dict = {}

    def __call__(cls, *args, **kwargs):  # type: ignore
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
