from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.redemptions.tests.factories import make_position
from src.redemptions.typings import Allocator, OsTokenPosition, VaultOsTokenPosition


class TestOsTokenPositionCodec:
    def test_round_trip(self) -> None:
        position = make_position()

        restored = OsTokenPosition.from_dict(position.as_dict(), index=position.index)

        assert restored.owner == position.owner
        assert restored.vault == position.vault
        assert restored.leaf_shares == position.leaf_shares

    def test_from_dict_propagates_index(self) -> None:
        position = make_position()

        restored = OsTokenPosition.from_dict(position.as_dict(), index=5)

        assert restored.index == 5

    def test_from_dict_checksums_lowercase_addresses(self) -> None:
        owner = faker.eth_address()
        vault = faker.eth_address()

        restored = OsTokenPosition.from_dict(
            {'owner': owner.lower(), 'vault': vault.lower(), 'leaf_shares': '1000'}
        )

        assert restored.owner == owner
        assert restored.vault == vault


class TestAllocator:
    def test_kept_shares_sums_wallet_locked_and_residual(self) -> None:
        allocator = Allocator(
            address=Web3.to_checksum_address(faker.eth_address()),
            vault_os_token_positions=[],
            residual_boosted_shares=Wei(10),
            wallet_shares=Wei(20),
            locked_shares=Wei(30),
        )

        assert allocator.kept_shares == Wei(60)

    def test_redeemable_shares_floors_at_zero(self) -> None:
        vault = Web3.to_checksum_address(faker.eth_address())
        allocator = Allocator(
            address=Web3.to_checksum_address(faker.eth_address()),
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault, minted_shares=Wei(100), ltv=0.5),
            ],
            wallet_shares=Wei(150),
        )

        assert allocator.redeemable_shares == Wei(0)

    def test_iter_vault_slices_splits_proportionally_with_dust_on_last_vault(self) -> None:
        vault_1 = Web3.to_checksum_address(faker.eth_address())
        vault_2 = Web3.to_checksum_address(faker.eth_address())
        allocator = Allocator(
            address=Web3.to_checksum_address(faker.eth_address()),
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(333), ltv=0.5),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(666), ltv=0.5),
            ],
            wallet_shares=Wei(100),
        )

        slices = list(allocator.iter_vault_slices(Wei(0)))

        assert [(s.vault_position.address, s.amount) for s in slices] == [
            (vault_1, Wei(299)),
            (vault_2, Wei(600)),
        ]

    def test_iter_vault_slices_drops_slices_below_minimum_but_keeps_them_in_dust_calc(
        self,
    ) -> None:
        vault_1 = Web3.to_checksum_address(faker.eth_address())
        vault_2 = Web3.to_checksum_address(faker.eth_address())
        allocator = Allocator(
            address=Web3.to_checksum_address(faker.eth_address()),
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(10), ltv=0.5),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(990), ltv=0.5),
            ],
        )

        slices = list(allocator.iter_vault_slices(Wei(15)))

        assert [(s.vault_position.address, s.amount) for s in slices] == [(vault_2, Wei(990))]

    def test_iter_vault_slices_yields_nothing_when_fully_kept(self) -> None:
        vault = Web3.to_checksum_address(faker.eth_address())
        allocator = Allocator(
            address=Web3.to_checksum_address(faker.eth_address()),
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault, minted_shares=Wei(100), ltv=0.5),
            ],
            wallet_shares=Wei(100),
        )

        assert not list(allocator.iter_vault_slices(Wei(0)))
