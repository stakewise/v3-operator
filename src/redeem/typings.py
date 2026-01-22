import dataclasses
from dataclasses import dataclass

from eth_typing import ChecksumAddress, HexStr
from web3 import Web3
from web3.types import Wei


@dataclass
class VaultShares:
    address: ChecksumAddress
    minted_shares: Wei


@dataclass
class Allocator:
    address: ChecksumAddress
    vault_shares: list[VaultShares]

    @property
    def total_shares(self) -> Wei:
        return Wei(sum(s.minted_shares for s in self.vault_shares))

    @property
    def vaults_proportions(self) -> dict[ChecksumAddress, float]:
        total = self.total_shares
        if total == 0:
            return {}
        return {s.address: s.minted_shares / total for s in self.vault_shares}


@dataclass
class LeverageStrategyPosition:
    user: ChecksumAddress
    vault: ChecksumAddress
    proxy: ChecksumAddress
    os_token_shares: Wei
    exiting_os_token_shares: Wei
    assets: Wei
    exiting_assets: Wei

    @classmethod
    def from_graph(cls, data: dict) -> 'LeverageStrategyPosition':
        return LeverageStrategyPosition(
            user=Web3.to_checksum_address(data['user']),
            vault=Web3.to_checksum_address(data['vault']['id']),
            proxy=Web3.to_checksum_address(data['proxy']),
            os_token_shares=Wei(int(data['osTokenShares'])),
            exiting_os_token_shares=Wei(int(data['exitingOsTokenShares'])),
            assets=Wei(int(data['assets'])),
            exiting_assets=Wei(int(data['exitingAssets'])),
        )


@dataclass
class RedeemablePosition:
    owner: ChecksumAddress
    vault: ChecksumAddress
    amount: Wei
    redeemable_shares: Wei = Wei(0)

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)

    @property
    def merkle_leaf(self) -> tuple[ChecksumAddress, ChecksumAddress, Wei]:
        return self.owner, self.vault, self.amount


@dataclass
class RedeemablePositionsMeta:
    merkle_root: HexStr
    ipfs_hash: str


@dataclass
class OsTokenPosition:
    owner: ChecksumAddress
    vault: ChecksumAddress
    leaf_shares: Wei
    shares_to_redeem: Wei
