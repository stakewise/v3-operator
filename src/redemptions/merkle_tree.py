from eth_typing import ChecksumAddress, HexStr
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from web3.types import Wei

from src.redemptions.typings import LEAF_TYPES, OsTokenPosition


class PositionsMerkleTree:
    def __init__(self, all_positions: list[OsTokenPosition], leaf_nonce: int):
        self.leaf_nonce = leaf_nonce
        self._tree = StandardMerkleTree.of(
            [p.merkle_leaf(leaf_nonce) for p in all_positions],
            LEAF_TYPES,
        )

    @property
    def root(self) -> HexStr:
        return self._tree.root

    def get_multi_proof(
        self, positions_to_redeem: list[OsTokenPosition]
    ) -> MultiProof[tuple[int, ChecksumAddress, Wei, ChecksumAddress]]:
        """Build a merkle multiproof proving the given positions to redeem."""
        redeem_leaves = [p.merkle_leaf(self.leaf_nonce) for p in positions_to_redeem]
        return self._tree.get_multi_proof(redeem_leaves)
