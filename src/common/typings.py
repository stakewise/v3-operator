from dataclasses import dataclass
from enum import Enum

from hexbytes import HexBytes
from sw_utils import ValidatorStatus
from web3.types import HexStr, Wei


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


class ValidatorType(Enum):
    ONE = '0x01'
    TWO = '0x02'


@dataclass
class Validator:
    public_key: HexStr
    index: int
    balance: int  # gwei
    withdrawal_credentials: str
    status: ValidatorStatus

    @property
    def validator_type(self) -> ValidatorType:
        if self.withdrawal_credentials.startswith('0x02'):
            return ValidatorType.TWO
        return ValidatorType.ONE


class Singleton(type):
    _instances: dict = {}

    def __call__(cls, *args, **kwargs):  # type: ignore
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
