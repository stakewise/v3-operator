from sw_utils.tests import faker

from src.redemptions.tests.factories import make_position
from src.redemptions.typings import OsTokenPosition


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
