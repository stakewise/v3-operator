import pytest
from eth_typing import BlockNumber
from sw_utils.tests import faker

from src.config.settings import settings
from src.validators.database import (
    CheckpointCrud,
    NetworkValidatorCrud,
    VaultValidatorCrud,
)
from src.validators.typings import NetworkValidator, VaultValidator


@pytest.fixture
def network_validator_crud(fake_settings):
    crud = NetworkValidatorCrud()
    crud.setup()
    yield crud
    settings.database.unlink(missing_ok=True)


@pytest.fixture
def checkpoint_crud(fake_settings):
    crud = CheckpointCrud()
    crud.setup()
    yield crud
    settings.database.unlink(missing_ok=True)


@pytest.fixture
def vault_validator_crud(fake_settings):
    crud = VaultValidatorCrud()
    crud.setup()
    yield crud
    settings.database.unlink(missing_ok=True)


class TestNetworkValidatorCrud:
    def test_setup_creates_table(self, network_validator_crud):
        # Should not raise on second call
        network_validator_crud.setup()

    def test_save_and_get_last(self, network_validator_crud):
        pk1 = faker.validator_public_key()
        pk2 = faker.validator_public_key()
        pk3 = faker.validator_public_key()
        validators = [
            NetworkValidator(public_key=pk1, block_number=BlockNumber(10)),
            NetworkValidator(public_key=pk2, block_number=BlockNumber(20)),
            NetworkValidator(public_key=pk3, block_number=BlockNumber(15)),
        ]
        network_validator_crud.save_network_validators(validators)

        last = network_validator_crud.get_last_network_validator()
        assert last is not None
        assert last.public_key == pk2
        assert last.block_number == BlockNumber(20)

    def test_get_last_empty(self, network_validator_crud):
        result = network_validator_crud.get_last_network_validator()
        assert result is None

    def test_is_validator_registered(self, network_validator_crud):
        pk = faker.validator_public_key()
        validators = [NetworkValidator(public_key=pk, block_number=BlockNumber(1))]
        network_validator_crud.save_network_validators(validators)

        assert network_validator_crud.is_validator_registered(pk)
        other_pk = faker.validator_public_key()
        assert not network_validator_crud.is_validator_registered(other_pk)

    def test_save_duplicate_ignored(self, network_validator_crud):
        pk = faker.validator_public_key()
        validators = [NetworkValidator(public_key=pk, block_number=BlockNumber(1))]
        network_validator_crud.save_network_validators(validators)
        # Should not raise on duplicate insert
        network_validator_crud.save_network_validators(validators)

        assert network_validator_crud.is_validator_registered(pk)

    def test_next_index_empty_table(self, network_validator_crud):
        index = network_validator_crud.get_next_validator_index([])
        assert index == 0

    def test_next_index_with_existing(self, network_validator_crud):
        pk1 = faker.validator_public_key()
        pk2 = faker.validator_public_key()
        pk3 = faker.validator_public_key()
        validators = [
            NetworkValidator(public_key=pk1, block_number=BlockNumber(1)),
            NetworkValidator(public_key=pk2, block_number=BlockNumber(2)),
            NetworkValidator(public_key=pk3, block_number=BlockNumber(3)),
        ]
        network_validator_crud.save_network_validators(validators)

        # No latest keys - count all existing (3) + 0
        index = network_validator_crud.get_next_validator_index([])
        assert index == 3

    def test_next_index_with_latest_keys(self, network_validator_crud):
        pk1 = faker.validator_public_key()
        pk2 = faker.validator_public_key()
        pk3 = faker.validator_public_key()
        validators = [
            NetworkValidator(public_key=pk1, block_number=BlockNumber(1)),
            NetworkValidator(public_key=pk2, block_number=BlockNumber(2)),
            NetworkValidator(public_key=pk3, block_number=BlockNumber(3)),
        ]
        network_validator_crud.save_network_validators(validators)

        # Exclude pk2, pk3: count=1 (pk1) + 2 latest
        idx = network_validator_crud.get_next_validator_index([pk2, pk3])
        assert idx == 3

    def test_next_index_exclude_all(self, network_validator_crud):
        pk1 = faker.validator_public_key()
        pk2 = faker.validator_public_key()
        validators = [
            NetworkValidator(public_key=pk1, block_number=BlockNumber(1)),
            NetworkValidator(public_key=pk2, block_number=BlockNumber(2)),
        ]
        network_validator_crud.save_network_validators(validators)

        # Exclude all: count=0 + 2 latest
        idx = network_validator_crud.get_next_validator_index([pk1, pk2])
        assert idx == 2

    def test_next_index_with_unknown_latest_keys(self, network_validator_crud):
        pk1 = faker.validator_public_key()
        validators = [
            NetworkValidator(public_key=pk1, block_number=BlockNumber(1)),
        ]
        network_validator_crud.save_network_validators(validators)

        unknown_pk = faker.validator_public_key()
        # unknown_pk is not in DB, so NOT IN excludes nothing -> count=1
        # index = count(1) + len(latest_public_keys)(1) = 2
        idx = network_validator_crud.get_next_validator_index([unknown_pk])
        assert idx == 2

    def test_table_name_uses_network(self, network_validator_crud):
        expected = f'{settings.network}_network_validators'
        assert network_validator_crud.NETWORK_VALIDATORS_TABLE == expected


class TestCheckpointCrud:
    def test_setup_creates_table(self, checkpoint_crud):
        checkpoint_crud.setup()

    def test_save_and_get_checkpoint(self, checkpoint_crud):
        checkpoint_crud.save_checkpoint()

        checkpoint = checkpoint_crud.get_checkpoint()
        genesis = settings.network_config.KEEPER_GENESIS_BLOCK
        assert checkpoint == genesis

    def test_get_checkpoint_empty(self, checkpoint_crud):
        result = checkpoint_crud.get_checkpoint()
        assert result is None

    def test_update_checkpoint(self, checkpoint_crud):
        checkpoint_crud.save_checkpoint()

        new_block = BlockNumber(99999)
        checkpoint_crud.update_checkpoint(new_block)

        cp = checkpoint_crud.get_checkpoint()
        assert cp == new_block

    def test_update_replaces_existing(self, checkpoint_crud):
        checkpoint_crud.save_checkpoint()

        checkpoint_crud.update_checkpoint(BlockNumber(100))
        checkpoint_crud.update_checkpoint(BlockNumber(200))

        cp = checkpoint_crud.get_checkpoint()
        assert cp == BlockNumber(200)

    def test_save_checkpoint_idempotent(self, checkpoint_crud):
        checkpoint_crud.save_checkpoint()
        checkpoint_crud.save_checkpoint()

        from src.common.clients import db_client

        with db_client.get_db_connection() as conn:
            count = conn.execute(
                f'SELECT COUNT(*) FROM {checkpoint_crud.CHECKPOINTS_TABLE}'
            ).fetchone()[0]
        assert count == 1

    def test_table_name_uses_network(self, checkpoint_crud):
        expected = f'{settings.network}_checkpoints'
        assert checkpoint_crud.CHECKPOINTS_TABLE == expected

    def test_migrate_drops_v2_column(self, fake_settings):
        from src.common.clients import db_client

        crud = CheckpointCrud()
        table = crud.CHECKPOINTS_TABLE
        # Create legacy 2-column table
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {table} (
                    checkpoint_validators INTEGER NOT NULL,
                    checkpoint_v2_validators INTEGER NOT NULL
                )
                """
            )
            conn.execute(f'INSERT INTO {table} VALUES (100, 100)')

        # setup() should migrate the table
        crud.setup()

        with db_client.get_db_connection() as conn:
            cols = [row[1] for row in conn.execute(f'PRAGMA table_info({table})').fetchall()]
            assert 'checkpoint_v2_validators' not in cols
            assert 'checkpoint_validators' in cols

            val = conn.execute(f'SELECT checkpoint_validators FROM {table}').fetchone()
            assert val[0] == 100

        settings.database.unlink(missing_ok=True)


class TestVaultValidatorCrud:
    def test_setup_creates_table(self, vault_validator_crud):
        vault_validator_crud.setup()

    def test_save_and_get(self, vault_validator_crud):
        pk1 = faker.validator_public_key()
        pk2 = faker.validator_public_key()
        pk3 = faker.validator_public_key()
        validators = [
            VaultValidator(public_key=pk1, block_number=BlockNumber(30)),
            VaultValidator(public_key=pk2, block_number=BlockNumber(10)),
            VaultValidator(public_key=pk3, block_number=BlockNumber(20)),
        ]
        vault_validator_crud.save_vault_validators(validators)

        result = vault_validator_crud.get_vault_validators()
        assert len(result) == 3
        # Should be ordered by block_number ascending
        assert result[0].block_number == BlockNumber(10)
        assert result[1].block_number == BlockNumber(20)
        assert result[2].block_number == BlockNumber(30)

    def test_get_empty(self, vault_validator_crud):
        result = vault_validator_crud.get_vault_validators()
        assert result == []

    def test_save_duplicate_ignored(self, vault_validator_crud):
        pk = faker.validator_public_key()
        validators = [VaultValidator(public_key=pk, block_number=BlockNumber(1))]
        vault_validator_crud.save_vault_validators(validators)
        vault_validator_crud.save_vault_validators(validators)

        result = vault_validator_crud.get_vault_validators()
        assert len(result) == 1

    def test_table_name_uses_network(self, vault_validator_crud):
        expected = f'{settings.network}_vault_validators'
        table = vault_validator_crud.VAULT_VALIDATORS_TABLE
        assert table == expected
