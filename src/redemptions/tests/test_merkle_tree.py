from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.tests.factories import make_position


class TestPositionsMerkleTree:
    def test_single_position(self) -> None:
        position = make_position(leaf_shares=1000, processed_shares=500)
        result = PositionsMerkleTree([position], nonce=5).get_multi_proof([position])
        assert len(result.leaves) == 1

    def test_partial_redeem(self) -> None:
        pos1 = make_position(leaf_shares=1000, processed_shares=500)
        pos2 = make_position(leaf_shares=2000, processed_shares=1000)

        result = PositionsMerkleTree([pos1, pos2], nonce=5).get_multi_proof([pos1])
        assert len(result.leaves) == 1
        assert len(result.proof) > 0

    def test_all_positions_redeemed(self) -> None:
        pos1 = make_position(leaf_shares=1000, processed_shares=500)
        pos2 = make_position(leaf_shares=2000, processed_shares=1000)

        result = PositionsMerkleTree([pos1, pos2], nonce=5).get_multi_proof([pos1, pos2])
        assert len(result.leaves) == 2
