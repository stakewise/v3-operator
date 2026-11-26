import dataclasses
import json
import logging
from contextlib import contextmanager
from sqlite3 import Connection
from typing import Iterator

from eth_typing import BlockNumber, HexStr

from src.common.clients import db_client
from src.config.settings import settings
from src.validators.typings import BuilderDeposit, NetworkValidator, VaultValidator

logger = logging.getLogger(__name__)


@contextmanager
def transaction() -> Iterator[Connection]:
    """
    Commits on success and rolls back on error.
    Pass the connection to the CRUD classes to run their queries in one transaction.
    """
    with db_client.get_db_connection() as connection:
        yield connection


class _ConnectionCrud:
    """A CRUD that runs in the given transaction, or opens its own connection per query."""

    def __init__(self, connection: Connection | None = None) -> None:
        self._connection = connection

    @contextmanager
    def _connect(self) -> Iterator[Connection]:
        if self._connection is not None:
            yield self._connection
            return
        with db_client.get_db_connection() as connection:
            yield connection


class NetworkValidatorCrud(_ConnectionCrud):
    @property
    def NETWORK_VALIDATORS_TABLE(self) -> str:
        return f'{settings.network}_network_validators'

    def save_network_validators(self, validators: list[NetworkValidator]) -> None:
        """Saves network validators."""
        with self._connect() as conn:
            conn.executemany(
                f'INSERT INTO {self.NETWORK_VALIDATORS_TABLE} '
                ' VALUES(:public_key, :block_number) ON CONFLICT DO NOTHING',
                [
                    {'public_key': val.public_key, 'block_number': val.block_number}
                    for val in validators
                ],
            )

    def delete_network_validators(self, public_keys: list[HexStr]) -> None:
        """Deletes network validators by public keys."""
        if not public_keys:
            return
        with self._connect() as conn:
            conn.execute(
                f'''DELETE FROM {self.NETWORK_VALIDATORS_TABLE}
                    WHERE public_key IN (SELECT value FROM json_each(?))''',
                (json.dumps(public_keys),),
            )

    def delete_all_network_validators(self) -> None:
        with self._connect() as conn:
            conn.execute(f'DELETE FROM {self.NETWORK_VALIDATORS_TABLE}')

    def get_registered_public_keys(self, public_keys: list[HexStr]) -> set[HexStr]:
        """Returns the public keys from the list that are registered."""
        if not public_keys:
            return set()
        with self._connect() as conn:
            rows = conn.execute(
                f'''SELECT public_key FROM {self.NETWORK_VALIDATORS_TABLE}
                    WHERE public_key IN (SELECT value FROM json_each(?))''',
                (json.dumps(public_keys),),
            ).fetchall()
        return {row[0] for row in rows}

    def get_last_network_validator(self) -> NetworkValidator | None:
        """Fetches last network validator."""
        network_validators_table = self.NETWORK_VALIDATORS_TABLE
        with self._connect() as conn:
            res = conn.execute(
                f'''SELECT public_key, block_number
                    FROM {network_validators_table} ORDER BY block_number DESC LIMIT 1'''
            ).fetchone()
            if res:
                return NetworkValidator(public_key=res[0], block_number=res[1])
            return None

    def is_validator_registered(self, public_key: HexStr) -> bool:
        """Checks whether validator is registered."""
        network_validators_table = self.NETWORK_VALIDATORS_TABLE
        with self._connect() as conn:
            res = conn.execute(
                f'SELECT public_key FROM {network_validators_table} WHERE (public_key = ?)',
                (public_key,),
            )
            return res.fetchone() is not None

    def get_next_validator_index(self, latest_public_keys: list[HexStr]) -> int:
        """Retrieves the index for the next validator."""
        with self._connect() as conn:
            if latest_public_keys:
                cur = conn.execute(
                    f'''SELECT COUNT(*) FROM {self.NETWORK_VALIDATORS_TABLE}
                        WHERE public_key NOT IN ({','.join(['?'] * len(latest_public_keys))})''',
                    latest_public_keys,
                )
            else:
                cur = conn.execute(f'SELECT COUNT(*) FROM {self.NETWORK_VALIDATORS_TABLE}')

            index = cur.fetchone()[0]

        return index + len(latest_public_keys)

    def setup(self) -> None:
        """Creates tables."""
        with self._connect() as conn:
            conn.execute(
                f"""
                        CREATE TABLE IF NOT EXISTS {self.NETWORK_VALIDATORS_TABLE} (
                            public_key VARCHAR(98) UNIQUE NOT NULL,
                            block_number INTEGER NOT NULL
                        )
                        """
            )


class BuilderDepositCrud(_ConnectionCrud):
    @property
    def BUILDER_DEPOSITS_TABLE(self) -> str:
        return f'{settings.network}_builder_deposits'

    def get_builder_deposits(self) -> list[BuilderDeposit]:
        with self._connect() as conn:
            rows = conn.execute(
                f'SELECT public_key, block_number FROM {self.BUILDER_DEPOSITS_TABLE} '
                'ORDER BY block_number'
            ).fetchall()
        return [BuilderDeposit(public_key=row[0], block_number=row[1]) for row in rows]

    def has_builder_deposits(self) -> bool:
        with self._connect() as conn:
            row = conn.execute(f'SELECT 1 FROM {self.BUILDER_DEPOSITS_TABLE} LIMIT 1').fetchone()
        return row is not None

    def save_builder_deposits(self, deposits: list[BuilderDeposit]) -> None:
        """Saves builder deposits, keeps the first deposit block of each public key."""
        with self._connect() as conn:
            conn.executemany(
                f'INSERT INTO {self.BUILDER_DEPOSITS_TABLE} '
                ' VALUES(:public_key, :block_number) ON CONFLICT DO NOTHING',
                [dataclasses.asdict(deposit) for deposit in deposits],
            )

    def delete_all_builder_deposits(self) -> None:
        with self._connect() as conn:
            conn.execute(f'DELETE FROM {self.BUILDER_DEPOSITS_TABLE}')

    def setup(self) -> None:
        """Creates tables."""
        with self._connect() as conn:
            conn.execute(
                f"""
                    CREATE TABLE IF NOT EXISTS {self.BUILDER_DEPOSITS_TABLE} (
                        public_key VARCHAR(98) UNIQUE NOT NULL,
                        block_number INTEGER NOT NULL
                    )
                """
            )


class CheckpointCrud(_ConnectionCrud):
    CHECKPOINT_VALIDATORS = 'checkpoint_validators'

    # Last block of the network validators deposit events scan.
    CHECKPOINT_NETWORK_VALIDATORS = 'checkpoint_network_validators'

    # Glamsterdam epoch at which the builders onboarded at the fork were resolved.
    CHECKPOINT_BUILDERS_ONBOARDING = 'checkpoint_builders_onboarding'

    # Set when network validators were scanned with the builder deposits filter from the start.
    CHECKPOINT_BUILDER_DEPOSITS_FILTER = 'checkpoint_builder_deposits_filter'

    @property
    def CHECKPOINTS_TABLE(self) -> str:
        return f'{settings.network}_checkpoints'

    def get_checkpoint(self, name: str) -> int | None:
        with self._connect() as conn:
            result = conn.execute(
                f'SELECT block FROM {self.CHECKPOINTS_TABLE} WHERE name = :name',
                {'name': name},
            ).fetchone()
        return result[0] if result else None

    def update_checkpoint(self, name: str, value: int) -> None:
        """Advances the checkpoint. Never lowers it."""
        with self._connect() as conn:
            conn.execute(
                f'''INSERT INTO {self.CHECKPOINTS_TABLE} (name, block)
                    VALUES (:name, :block)
                    ON CONFLICT(name) DO UPDATE SET block = MAX(block, :block)''',
                {'name': name, 'block': value},
            )

    def delete_checkpoint(self, name: str) -> None:
        with self._connect() as conn:
            conn.execute(f'DELETE FROM {self.CHECKPOINTS_TABLE} WHERE name = :name', {'name': name})

    def get_validators_checkpoint(self) -> BlockNumber | None:
        checkpoint = self.get_checkpoint(self.CHECKPOINT_VALIDATORS)
        return BlockNumber(checkpoint) if checkpoint is not None else None

    def update_validators_checkpoint(self, block_number: BlockNumber) -> None:
        self.update_checkpoint(self.CHECKPOINT_VALIDATORS, block_number)

    def setup(self) -> None:
        """Creates tables and migrates from old schema if needed."""
        self._migrate()
        with db_client.get_db_connection() as conn:
            self._create_table(conn)

    def _migrate(self) -> None:
        """Migrates from old (checkpoint_validators, checkpoint_v2_validators) schema."""
        with db_client.get_db_connection() as conn:
            cursor = conn.execute(f'PRAGMA table_info({self.CHECKPOINTS_TABLE})')
            columns = {row[1] for row in cursor.fetchall()}

            if 'checkpoint_validators' not in columns:
                return

            row = conn.execute(
                f'SELECT checkpoint_validators FROM {self.CHECKPOINTS_TABLE} LIMIT 1'
            ).fetchone()
            conn.execute(f'DROP TABLE {self.CHECKPOINTS_TABLE}')
            self._create_table(conn)
            if row:
                conn.execute(
                    f'''INSERT INTO {self.CHECKPOINTS_TABLE} (name, block)
                        VALUES (:name, :block)''',
                    {'name': self.CHECKPOINT_VALIDATORS, 'block': row[0]},
                )

    def _create_table(self, conn: Connection) -> None:
        conn.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.CHECKPOINTS_TABLE} (
                name TEXT NOT NULL UNIQUE,
                block INTEGER NOT NULL
            )"""
        )


class VaultValidatorCrud:
    @property
    def VAULT_VALIDATORS_TABLE(self) -> str:
        return f'{settings.network}_vault_validators'

    def save_vault_validators(self, validators: list[VaultValidator]) -> None:
        with db_client.get_db_connection() as conn:
            conn.executemany(
                f'INSERT INTO {self.VAULT_VALIDATORS_TABLE} '
                ' VALUES(:public_key, :block_number) ON CONFLICT DO NOTHING',
                [
                    {'public_key': val.public_key, 'block_number': val.block_number}
                    for val in validators
                ],
            )

    def get_vault_validators(self) -> list[VaultValidator]:
        vault_validators_table = self.VAULT_VALIDATORS_TABLE
        with db_client.get_db_connection() as conn:
            results = conn.execute(
                f'''SELECT public_key, block_number
                    FROM {vault_validators_table}
                    ORDER BY block_number''',
            ).fetchall()
            return [VaultValidator(public_key=res[0], block_number=res[1]) for res in results]

    def setup(self) -> None:
        """Creates tables."""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                        CREATE TABLE IF NOT EXISTS {self.VAULT_VALIDATORS_TABLE} (
                            public_key VARCHAR(98) UNIQUE NOT NULL,
                            block_number INTEGER NOT NULL
                        )
                        """
            )
