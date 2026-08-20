from dataclasses import dataclass

from eth_typing import ChecksumAddress, HexStr
from multiproof.standard import standard_leaf_hash
from web3 import Web3
from web3.types import Wei

LEAF_TYPES = ['uint256', 'address', 'uint256', 'address']


@dataclass
class VaultOsTokenPosition:
    address: ChecksumAddress
    minted_shares: Wei
    ltv: float
    # part of the minted shares that backs a leverage strategy position
    boosted_shares: Wei = Wei(0)

    @property
    def redeemable_shares(self) -> Wei:
        return Wei(max(0, self.minted_shares - self.boosted_shares))


@dataclass
class Allocator:
    address: ChecksumAddress
    vault_os_token_positions: list[VaultOsTokenPosition]
    # boosted shares that couldn't be matched against a same-vault mint
    residual_boosted_shares: Wei = Wei(0)

    @property
    def total_redeemable_shares(self) -> Wei:
        return Wei(sum(s.redeemable_shares for s in self.vault_os_token_positions))

    @property
    def vaults_proportions(self) -> dict[ChecksumAddress, float]:
        total = self.total_redeemable_shares
        if total == 0:
            return {}
        return {s.address: s.redeemable_shares / total for s in self.vault_os_token_positions}

    def get_vault_position(self, vault: ChecksumAddress) -> VaultOsTokenPosition | None:
        return next((vs for vs in self.vault_os_token_positions if vs.address == vault), None)


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
    """
    Represents leaf shares to redeem for a given vault and owner.
    Mirrors the OsTokenPosition structure from the OsTokenRedeemer contract.
    Note: This is distinct from the OsTokenPosition in the VaultOsToken contract,
    which represents a debt position.
    """

    owner: ChecksumAddress
    vault: ChecksumAddress
    leaf_shares: Wei
    # Zero-based index of the position in the IPFS positions file. Used for logging only.
    index: int = 0
    processed_shares: Wei = Wei(0)
    shares_to_redeem: Wei = Wei(0)

    @property
    def unprocessed_shares(self) -> Wei:
        return Wei(max(0, self.leaf_shares - self.processed_shares))

    def as_dict(self) -> dict:
        return {
            'owner': self.owner,
            'vault': self.vault,
            'leaf_shares': str(self.leaf_shares),
        }

    def merkle_leaf(self, nonce: int) -> tuple[int, ChecksumAddress, Wei, ChecksumAddress]:
        return nonce, self.vault, self.leaf_shares, self.owner

    def leaf_hash(self, nonce: int) -> bytes:
        """Get the Merkle leaf hash"""
        return standard_leaf_hash(
            values=(nonce, self.vault, self.leaf_shares, self.owner),
            types=LEAF_TYPES,
        )


@dataclass
class ApiConfig:
    source: str
    sleep_timeout: float
    access_key: str | None = None


@dataclass
class RedeemablePositions:
    merkle_root: HexStr
    ipfs_hash: str
