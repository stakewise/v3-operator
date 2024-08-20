from dataclasses import dataclass

from web3.types import Wei


@dataclass
class RewardVoteInfo:
    rewards_root: bytes
    ipfs_hash: str


@dataclass
class HarvestParams:
    rewards_root: bytes
    reward: Wei
    unlocked_mev_reward: Wei
    proof: list[bytes]


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


class Singleton(type):
    _instances: dict = {}

    def __call__(cls, *args, **kwargs):  # type: ignore
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
