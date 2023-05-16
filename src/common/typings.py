from dataclasses import dataclass

from Cryptodome.PublicKey import RSA
from eth_typing import ChecksumAddress
from web3.types import Wei


@dataclass
class Oracles:
    threshold: int
    addresses: list[ChecksumAddress]
    rsa_public_keys: list[RSA.RsaKey]
    endpoints: list[str]


@dataclass
class RewardVoteInfo:
    rewards_root: bytes
    ipfs_hash: str


@dataclass
class HarvestParams:
    rewards_root: bytes
    reward: Wei
    proof: list[bytes]
