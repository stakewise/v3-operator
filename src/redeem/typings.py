import dataclasses
from dataclasses import dataclass

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.types import Wei


@dataclass
class Allocator:
    address: ChecksumAddress
    vault: ChecksumAddress
    minted_shares: Wei

    @classmethod
    def from_graph(cls, data: dict) -> 'Allocator':
        return Allocator(
            vault=Web3.to_checksum_address(data['vault']['id']),
            address=Web3.to_checksum_address(data['address']),
            minted_shares=Wei(int(data['mintedOsTokenShares'])),
        )


@dataclass
class RedeemablePosition:
    owner: ChecksumAddress
    vault: ChecksumAddress
    amount: Wei

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)
