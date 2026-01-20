from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.commands.internal.update_redeemable_positions import (
    _reduce_boosted_amount,
    calculate_boost_ostoken_shares,
    create_redeemable_positions,
)
from src.redeem.os_token_converter import OsTokenConverter
from src.redeem.typings import (
    Allocator,
    LeverageStrategyPosition,
    RedeemablePosition,
    VaultShares,
)


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


async def test_calculate_boost_ostoken_shares():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    proxy = faker.eth_address()

    os_token_converter = OsTokenConverter(105, 100)

    # empty case
    result = await calculate_boost_ostoken_shares(set(), [], os_token_converter)
    assert result == {}

    # filter by users
    leverage_positions = [
        LeverageStrategyPosition(
            user=address_1,
            vault=vault_1,
            proxy=proxy,
            os_token_shares=Wei(1000),
            exiting_os_token_shares=Wei(500),
            assets=Wei(200),
            exiting_assets=Wei(100),
        ),
        LeverageStrategyPosition(
            user=address_1,
            vault=vault_1,
            proxy=proxy,
            os_token_shares=Wei(1000),
            exiting_os_token_shares=Wei(500),
            assets=Wei(200),
            exiting_assets=Wei(100),
        ),
        LeverageStrategyPosition(
            user=address_2,
            vault=vault_1,
            proxy=proxy,
            os_token_shares=Wei(100),
            exiting_os_token_shares=Wei(0),
            assets=Wei(0),
            exiting_assets=Wei(0),
        ),
        LeverageStrategyPosition(
            user=address_2,
            vault=vault_2,
            proxy=proxy,
            os_token_shares=Wei(3000),
            exiting_os_token_shares=Wei(0),
            assets=Wei(100),
            exiting_assets=Wei(0),
        ),
    ]
    result = await calculate_boost_ostoken_shares(
        {address_1, address_2}, leverage_positions, os_token_converter
    )
    assert result == {address_1: {vault_1: 3570}, address_2: {vault_1: 100, vault_2: 3095}}


def test_reduces_boosted_amount():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    # empty case
    allocators = [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(1000)),
                VaultShares(address=vault_2, minted_shares=Wei(2000)),
            ],
        )
    ]
    boost_ostoken_shares = {}
    result = _reduce_boosted_amount(allocators, boost_ostoken_shares)
    assert result == [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(1000)),
                VaultShares(address=vault_2, minted_shares=Wei(2000)),
            ],
        )
    ]
    # basic reduction
    allocators = [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(500)),
            ],
        ),
        Allocator(
            address=address_2,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(1000)),
                VaultShares(address=vault_2, minted_shares=Wei(2000)),
            ],
        ),
    ]
    boost_ostoken_shares = {
        address_1: {
            vault_1: Wei(300),
        },
        address_2: {
            vault_1: Wei(500),
            vault_2: Wei(1500),
        },
    }
    result = _reduce_boosted_amount(allocators, boost_ostoken_shares)
    assert result == [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(200)),
            ],
        ),
        Allocator(
            address=address_2,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(500)),
                VaultShares(address=vault_2, minted_shares=Wei(500)),
            ],
        ),
    ]
