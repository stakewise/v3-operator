from eth_typing import ChecksumAddress
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from web3.types import Wei

from src.redemptions.typings import OsTokenPosition

LEAF_TYPES = ['uint256', 'address', 'uint256', 'address']


class PositionsMerkleTree:
    """Merkle tree built from all OsToken positions for a given redemption nonce.

    Building the tree from ALL positions makes its root match the on-chain
    redemption root. Multiproofs for the subset of positions being redeemed are
    generated via :meth:`get_multi_proof`.
    """

    def __init__(self, all_positions: list[OsTokenPosition], nonce: int):
        self.nonce = nonce
        self._tree = StandardMerkleTree.of(
            [p.merkle_leaf(nonce - 1) for p in all_positions],
            LEAF_TYPES,
        )

    def get_multi_proof(
        self, positions_to_redeem: list[OsTokenPosition]
    ) -> MultiProof[tuple[int, ChecksumAddress, Wei, ChecksumAddress]]:
        """Build a merkle multiproof proving the given positions to redeem."""
        redeem_leaves = [p.merkle_leaf(self.nonce - 1) for p in positions_to_redeem]
        return self._tree.get_multi_proof(redeem_leaves)
