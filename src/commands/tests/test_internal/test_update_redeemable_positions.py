from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.commands.internal.update_redeemable_positions import (
    create_redeemable_positions,
)
from src.redeem.typings import Allocator, RedeemablePosition, VaultShares


def test_create_redeemable_positions():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()

    # test zero allocators
    result = create_redeemable_positions([], {})
    assert result == []

    # test single vault
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(0),
    }
    result = create_redeemable_positions(allocators, kept_tokens)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150))]

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(100),
    }
    result = create_redeemable_positions(allocators, kept_tokens)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(50))]

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)),
            ],
        ),
        Allocator(
            address=Web3.to_checksum_address(address_2),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(75)),
            ],
        ),
    ]
    kept_tokens = {
        address_1: Wei(0),
        address_2: Wei(75),
    }
    result = create_redeemable_positions(allocators, kept_tokens)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150))]

    # test multiple vaults
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)),
                VaultShares(address=Web3.to_checksum_address(vault_2), minted_shares=Wei(150)),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(0),
    }
    result = create_redeemable_positions(allocators, kept_tokens)
    assert result == [
        RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150)),
        RedeemablePosition(owner=address_1, vault=vault_2, amount=Wei(150)),
    ]
