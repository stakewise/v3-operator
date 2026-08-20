from collections.abc import Iterator
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
    # osToken balance held in the owner's wallet, from the subgraph
    wallet_shares: Wei = Wei(0)
    # osToken locked in third-party protocols (Rabby/DeBank), from the API
    locked_shares: Wei = Wei(0)

    @property
    def total_redeemable_shares(self) -> Wei:
        return Wei(sum(s.redeemable_shares for s in self.vault_os_token_positions))

    @property
    def kept_shares(self) -> Wei:
        return Wei(self.wallet_shares + self.locked_shares + self.residual_boosted_shares)

    @property
    def redeemable_shares(self) -> Wei:
        return Wei(max(0, self.total_redeemable_shares - self.kept_shares))

    def get_vault_position(self, vault: ChecksumAddress) -> VaultOsTokenPosition | None:
        return next((vs for vs in self.vault_os_token_positions if vs.address == vault), None)

    def iter_vault_slices(self, min_shares: Wei) -> Iterator[tuple[VaultOsTokenPosition, Wei]]:
        """
        Split ``redeemable_shares`` across vaults proportionally to each vault's (post-boost)
        redeemable share of the total. The last vault absorbs the rounding dust. Slices below
        ``min_shares`` are dropped, but still count towards the running allocated total so the
        dust rule stays exact.
        """
        redeemable_amount = self.redeemable_shares
        if redeemable_amount == 0:
            return
        total = self.total_redeemable_shares
        allocated_amount = 0
        positions = self.vault_os_token_positions
        for index, position in enumerate(positions):
            if index == len(positions) - 1:
                vault_amount = max(0, int(redeemable_amount - allocated_amount))
            else:
                vault_amount = int(redeemable_amount * (position.redeemable_shares / total))
            allocated_amount += vault_amount
            if vault_amount < min_shares:
                continue
            yield position, Wei(vault_amount)


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
        """``as_dict``/``from_dict`` define the IPFS positions file schema (kept in one place)."""
        return {
            'owner': self.owner,
            'vault': self.vault,
            'leaf_shares': str(self.leaf_shares),
        }

    @classmethod
    def from_dict(cls, data: dict, index: int = 0) -> 'OsTokenPosition':
        return cls(
            owner=Web3.to_checksum_address(data['owner']),
            vault=Web3.to_checksum_address(data['vault']),
            leaf_shares=Wei(int(data['leaf_shares'])),
            index=index,
        )

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
