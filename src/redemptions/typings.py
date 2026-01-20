from dataclasses import dataclass

from eth_typing import ChecksumAddress, HexStr
from web3.types import Wei


@dataclass
class RedeemablePositions:
    merkle_root: HexStr
    ipfs_hash: str


@dataclass
class RedeemablePosition:
    owner: ChecksumAddress
    vault: ChecksumAddress
    amount: Wei
