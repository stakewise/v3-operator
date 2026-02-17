from dataclasses import dataclass

from eth_typing import ChecksumAddress, HexStr
from multiproof.standard import standard_leaf_hash
from web3 import Web3
from web3.types import Wei


@dataclass
class VaultOsTokenPosition:
    address: ChecksumAddress
    minted_shares: Wei
    ltv: float


@dataclass
class Allocator:
    address: ChecksumAddress
    vault_os_token_positions: list[VaultOsTokenPosition]

    @property
    def total_shares(self) -> Wei:
        return Wei(sum(s.minted_shares for s in self.vault_os_token_positions))

    @property
    def vaults_proportions(self) -> dict[ChecksumAddress, float]:
        total = self.total_shares
        if total == 0:
            return {}
        return {s.address: s.minted_shares / total for s in self.vault_os_token_positions}


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
class OsTokenPosition:
    owner: ChecksumAddress
    vault: ChecksumAddress
    amount: Wei
    redeemable_shares: Wei = Wei(0)

    def as_dict(self) -> dict:
        return {
            'owner': self.owner,
            'vault': self.vault,
            'amount': str(self.amount),
        }

    def merkle_leaf(self, nonce: int) -> tuple[int, ChecksumAddress, Wei, ChecksumAddress]:
        return nonce, self.vault, self.amount, self.owner

    def leaf_hash(self, nonce: int) -> bytes:
        """Get the Merkle leaf hash"""
        return standard_leaf_hash(
            values=(nonce, self.vault, self.amount, self.owner),
            types=['uint256', 'address', 'uint256', 'address'],
        )


@dataclass
class ApiConfig:
    source: str
    sleep_timeout: float
    access_key: str | None = None


@dataclass
class ArbitrumConfig:
    OS_TOKEN_CONTRACT_ADDRESS: ChecksumAddress
    EXECUTION_ENDPOINT: str


@dataclass
class RedeemablePositions:
    merkle_root: HexStr
    ipfs_hash: str
