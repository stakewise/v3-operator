from eth_typing import ChecksumAddress, HexStr
from sw_utils.tests import faker
from web3.types import Wei

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
    shares_to_redeem: int = 0,
) -> OsTokenPosition:
    return OsTokenPosition(
        vault=vault if vault is not None else faker.eth_address(),
        owner=owner if owner is not None else faker.eth_address(),
        leaf_shares=Wei(leaf_shares),
        processed_shares=Wei(processed_shares),
        shares_to_redeem=Wei(shares_to_redeem),
    )
