from pathlib import Path
from typing import Any

import pytest
from eth_typing import HexAddress

from src.config.networks import HOODI
from src.config.settings import settings
from src.remote_db.database import KeyPairsCrud
from src.remote_db.typings import RemoteDatabaseKeyPair


class _FakeCursor:
    def __init__(self, fetchone_result: Any = None, fetchall_result: Any = None) -> None:
        self.fetchone_result = fetchone_result
        self.fetchall_result = fetchall_result
        self.executed_sql: str | None = None
        self.executed_params: Any = None
        self.executemany_sql: str | None = None
        self.executemany_params: list[tuple] | None = None

    def execute(self, sql: str, params: Any = None) -> None:
        self.executed_sql = sql
        self.executed_params = params

    def executemany(self, sql: str, params_seq: list[tuple]) -> None:
        self.executemany_sql = sql
        self.executemany_params = params_seq

    def fetchone(self) -> Any:
        return self.fetchone_result

    def fetchall(self) -> Any:
        return self.fetchall_result

    def __enter__(self) -> '_FakeCursor':
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _FakeConnection:
    def __init__(self, cursor: _FakeCursor) -> None:
        self._cursor = cursor

    def cursor(self) -> _FakeCursor:
        return self._cursor


@pytest.fixture
def _init_settings(vault_address: HexAddress, data_dir: Path) -> None:
    settings.set(vault=vault_address, vault_dir=data_dir / 'vault', network=HOODI)


@pytest.mark.usefixtures('_init_settings')
class TestKeyPairsCrud:
    def test_get_keypairs_count_is_vault_scoped(self, vault_address: HexAddress):
        cursor = _FakeCursor(fetchone_result=(0,))
        crud = KeyPairsCrud(db_connection=_FakeConnection(cursor))

        crud.get_keypairs_count()

        assert 'WHERE vault = %s' in cursor.executed_sql
        assert cursor.executed_params == (vault_address,)

    def test_get_first_keypair_is_vault_scoped(self, vault_address: HexAddress):
        cursor = _FakeCursor(fetchone_result=None)
        crud = KeyPairsCrud(db_connection=_FakeConnection(cursor))

        crud.get_first_keypair()

        assert 'WHERE vault = %s' in cursor.executed_sql
        assert cursor.executed_params == (vault_address,)

    def test_get_keypairs_is_vault_scoped(self, vault_address: HexAddress):
        cursor = _FakeCursor(fetchall_result=[])
        crud = KeyPairsCrud(db_connection=_FakeConnection(cursor))

        crud.get_keypairs()

        assert 'WHERE vault = %(vault)s' in cursor.executed_sql
        assert 'ORDER BY public_key' in cursor.executed_sql
        assert cursor.executed_params == {'vault': vault_address}

    def test_remove_keypairs_without_args_is_vault_scoped(self, vault_address: HexAddress):
        cursor = _FakeCursor()
        crud = KeyPairsCrud(db_connection=_FakeConnection(cursor))

        crud.remove_keypairs()

        assert 'WHERE vault = %(vault)s' in cursor.executed_sql
        assert 'DELETE FROM' in cursor.executed_sql
        assert cursor.executed_params == {'vault': vault_address}

    def test_remove_keypairs_with_public_keys_is_vault_scoped(self, vault_address: HexAddress):
        cursor = _FakeCursor()
        crud = KeyPairsCrud(db_connection=_FakeConnection(cursor))

        crud.remove_keypairs(in_public_keys={'0x1'})

        assert 'vault = %(vault)s' in cursor.executed_sql
        assert 'public_key IN %(in_public_keys)s' in cursor.executed_sql
        assert cursor.executed_params['vault'] == vault_address
        assert cursor.executed_params['in_public_keys'] == ('0x1',)

    def test_upload_keypairs_arity_and_vault_scoping(self, vault_address: HexAddress):
        cursor = _FakeCursor()
        crud = KeyPairsCrud(db_connection=_FakeConnection(cursor))
        keypairs = [
            RemoteDatabaseKeyPair(public_key='0xpub1', private_key='0xpriv1', nonce='0xnonce1'),
            RemoteDatabaseKeyPair(public_key='0xpub2', private_key='0xpriv2', nonce='0xnonce2'),
        ]

        crud.upload_keypairs(keypairs)

        assert cursor.executemany_sql.count('%s') == 4
        assert 'vault' in cursor.executemany_sql
        assert 'public_key' in cursor.executemany_sql
        assert 'private_key' in cursor.executemany_sql
        assert 'nonce' in cursor.executemany_sql

        assert cursor.executemany_params is not None
        for param_tuple, keypair in zip(cursor.executemany_params, keypairs):
            assert len(param_tuple) == 4
            assert param_tuple[0] == vault_address
            assert param_tuple == (
                vault_address,
                keypair.public_key,
                keypair.private_key,
                keypair.nonce,
            )

    def test_create_table_includes_vault_column_and_migration(self):
        cursor = _FakeCursor()
        crud = KeyPairsCrud(db_connection=_FakeConnection(cursor))

        # create_table issues two separate execute calls: the CREATE TABLE and
        # the forward-migration ALTER. Track both by wrapping execute.
        executed_statements: list[str] = []
        original_execute = cursor.execute

        def _tracking_execute(sql: str, params: Any = None) -> None:
            executed_statements.append(sql)
            original_execute(sql, params)

        cursor.execute = _tracking_execute  # type: ignore[method-assign]

        crud.create_table()

        assert len(executed_statements) == 2
        create_sql, alter_sql = executed_statements
        assert 'CREATE TABLE IF NOT EXISTS' in create_sql
        assert 'vault' in create_sql
        assert 'UNIQUE (vault, public_key)' in create_sql
        assert 'ALTER TABLE' in alter_sql
        assert 'ADD COLUMN IF NOT EXISTS vault' in alter_sql
