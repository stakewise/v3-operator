from dataclasses import dataclass
from functools import cached_property

from eth_keys.datatypes import PublicKey
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from web3 import Web3
from web3.types import Wei


@dataclass
# pylint: disable-next=too-many-instance-attributes
class Oracles:
    rewards_threshold: int
    validators_threshold: int
    exit_signature_recover_threshold: int
    signature_validity_period: int
    public_keys: list[HexStr]
    endpoints: list[list[str]]

    validators_approval_batch_limit: int
    validators_exit_rotation_batch_limit: int

    @cached_property
    def addresses(self) -> list[ChecksumAddress]:
        res = []
        for public_key in self.public_keys:
            public_key_obj = PublicKey(Web3.to_bytes(hexstr=public_key))
            res.append(public_key_obj.to_checksum_address())
        return res


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
