from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

import pytest
from eth_typing import BlockNumber, HexStr
from sw_utils.tests import faker
from web3 import Web3

from src.config.networks import HOODI, NETWORKS
from src.config.settings import settings
from src.validators.tasks import (
    _parse_vault_validators_dump,
    fetch_vault_validators_public_keys,
)


@pytest.mark.usefixtures('fake_settings')
class TestParseVaultValidatorsDump:
    def test_filters_by_vault(self):
        ours = [faker.validator_public_key() for _ in range(2)]
        data = (
            _dump_record(10, settings.vault, ours[0])
            + _dump_record(11, faker.eth_address(), faker.validator_public_key())
            + _dump_record(12, settings.vault, ours[1])
        )

        public_keys = _parse_vault_validators_dump(data, settings.vault, BlockNumber(100))

        assert public_keys == ours

    def test_accepts_lowercase_vault(self):
        public_key = faker.validator_public_key()
        data = _dump_record(10, settings.vault.lower(), public_key)

        public_keys = _parse_vault_validators_dump(data, settings.vault, BlockNumber(100))

        assert public_keys == [public_key]

    def test_empty_dump(self):
        with pytest.raises(ValueError, match='Malformed vault validators dump'):
            _parse_vault_validators_dump(b'', settings.vault, BlockNumber(100))

    def test_truncated_record(self):
        data = _dump_record(10, settings.vault, faker.validator_public_key())

        with pytest.raises(ValueError, match='Malformed vault validators dump'):
            _parse_vault_validators_dump(data[:-1], settings.vault, BlockNumber(100))

    def test_unsorted_records(self):
        data = _dump_record(12, settings.vault, faker.validator_public_key()) + _dump_record(
            10, settings.vault, faker.validator_public_key()
        )

        with pytest.raises(ValueError, match='not sorted by block number'):
            _parse_vault_validators_dump(data, settings.vault, BlockNumber(100))

    def test_block_above_last_block(self):
        data = _dump_record(101, settings.vault, faker.validator_public_key())

        with pytest.raises(ValueError, match='above its last block'):
            _parse_vault_validators_dump(data, settings.vault, BlockNumber(100))


@pytest.mark.usefixtures('fake_settings')
class TestFetchVaultValidatorsPublicKeys:
    async def test_dump_and_events(self):
        dump_key = faker.validator_public_key()
        event_key = faker.validator_public_key()
        data = _dump_record(3_400_000, settings.vault, dump_key) + _dump_record(
            3_450_000, faker.eth_address(), faker.validator_public_key()
        )

        with (
            patch_vault_validators_dump(data),
            patch_vault_events([event_key]) as events_mock,
        ):
            public_keys = await fetch_vault_validators_public_keys(to_block=BlockNumber(3_600_000))

        assert public_keys == [dump_key, event_key]
        events_mock.assert_awaited_once_with(
            from_block=BlockNumber(3_500_001), to_block=BlockNumber(3_600_000)
        )

    async def test_without_dump(self):
        event_key = faker.validator_public_key()

        with (
            patch.object(NETWORKS[HOODI].CHECKPOINTS, 'VAULT_VALIDATORS_IPFS_HASH', ''),
            patch('src.validators.tasks._fetch_ipfs_dump', AsyncMock()) as fetch_mock,
            patch_vault_events([event_key]) as events_mock,
        ):
            public_keys = await fetch_vault_validators_public_keys(to_block=BlockNumber(3_600_000))

        assert public_keys == [event_key]
        fetch_mock.assert_not_awaited()
        events_mock.assert_awaited_once_with(
            from_block=NETWORKS[HOODI].KEEPER_GENESIS_BLOCK, to_block=BlockNumber(3_600_000)
        )


def _dump_record(block_number: int, vault: str, public_key: HexStr) -> bytes:
    return (
        block_number.to_bytes(4, 'big')
        + Web3.to_bytes(hexstr=vault)
        + Web3.to_bytes(hexstr=public_key)
    )


@contextmanager
def patch_vault_validators_dump(data: bytes, last_block: int = 3_500_000):
    with (
        patch.object(
            NETWORKS[HOODI].CHECKPOINTS, 'VAULT_VALIDATORS_IPFS_HASH', 'bafyvaultvalidators'
        ),
        patch.object(
            NETWORKS[HOODI].CHECKPOINTS, 'VAULT_VALIDATORS_LAST_BLOCK', BlockNumber(last_block)
        ),
        patch('src.validators.tasks._fetch_ipfs_dump', AsyncMock(return_value=data)) as fetch_mock,
    ):
        yield fetch_mock


@contextmanager
def patch_vault_events(public_keys: list[HexStr]):
    with patch(
        'src.validators.tasks.vault_contract.get_registered_validators_public_keys',
        AsyncMock(return_value=public_keys),
    ) as events_mock:
        yield events_mock
