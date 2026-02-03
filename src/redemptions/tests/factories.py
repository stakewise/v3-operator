from eth_typing import HexStr
from sw_utils.tests import faker

from src.redemptions.typings import RedeemablePositions


def create_redeemable_positions(
    merkle_root: HexStr | None = None, ipfs_hash: str | None = None
) -> RedeemablePositions:
    if merkle_root is None:
        merkle_root = faker.merkle_root()

    if ipfs_hash is None:
        ipfs_hash = faker.ipfs_hash()

    return RedeemablePositions(merkle_root=merkle_root, ipfs_hash=ipfs_hash)
