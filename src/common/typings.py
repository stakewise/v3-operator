from dataclasses import dataclass
from enum import Enum

from hexbytes import HexBytes
from web3.types import ChecksumAddress, Wei


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


class Singleton(type):
    _instances: dict = {}

    def __call__(cls, *args, **kwargs):  # type: ignore
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
