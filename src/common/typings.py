from dataclasses import dataclass

from eth_typing import BlockNumber
from web3.types import Wei


@dataclass
class OraclesCache:
    checkpoint_block: BlockNumber
    config: dict
    validators_threshold: int
    rewards_threshold: int


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
