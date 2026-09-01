from eth_typing import ChecksumAddress, HexStr
from sw_utils.tests import faker
from web3.types import Wei

from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.typings import OsTokenPosition, RedeemablePositions


def create_redeemable_positions(
    merkle_root: HexStr | None = None, ipfs_hash: str | None = None
) -> RedeemablePositions:
    if merkle_root is None:
        merkle_root = faker.merkle_root()

    if ipfs_hash is None:
        ipfs_hash = faker.ipfs_hash()

    return RedeemablePositions(merkle_root=merkle_root, ipfs_hash=ipfs_hash)


def make_position(
    vault: ChecksumAddress | None = None,
    owner: ChecksumAddress | None = None,
    leaf_shares: int = 1000,
    processed_shares: int = 500,
    shares_to_redeem: int | None = None,
    index: int = 0,
) -> OsTokenPosition:
    """Build a test position.

    ``processed_shares`` defaults to half of ``leaf_shares`` so redemption-loop
    tests don't silently no-op when a caller forgets to set it.

    ``shares_to_redeem`` defaults to ``leaf_shares - processed_shares``
    (i.e. unprocessed shares), mirroring what ``assign_shares_to_redeem`` would set
    before handing positions to ``redeem_positions``.  Pass an explicit value
    when testing the partial-fill or zero-withdrawable edge cases.
    """
    effective_shares_to_redeem = (
        shares_to_redeem if shares_to_redeem is not None else leaf_shares - processed_shares
    )
    return OsTokenPosition(
        vault=vault if vault is not None else faker.eth_address(),
        owner=owner if owner is not None else faker.eth_address(),
        leaf_shares=Wei(leaf_shares),
        index=index,
        processed_shares=Wei(processed_shares),
        shares_to_redeem=Wei(effective_shares_to_redeem),
    )


def make_tree(
    positions: list[OsTokenPosition] | None = None, nonce: int = 5
) -> PositionsMerkleTree:
    """Build a positions merkle tree. Defaults to a single position so callers that
    only need a valid tree (e.g. when tx_redeem_position is mocked) can omit it."""
    return PositionsMerkleTree(positions or [make_position()], leaf_nonce=nonce)
