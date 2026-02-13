import logging
from sqlite3 import Connection

from eth_typing import BlockNumber, HexStr

from src.common.clients import db_client
from src.config.settings import settings
from src.validators.typings import NetworkValidator, VaultValidator

logger = logging.getLogger(__name__)


class NetworkValidatorCrud:
    @property
    def NETWORK_VALIDATORS_TABLE(self) -> str:
        return f'{settings.network}_network_validators'

    def save_network_validators(self, validators: list[NetworkValidator]) -> None:
        """Saves network validators."""
        with db_client.get_db_connection() as conn:
            conn.executemany(
                f'INSERT INTO {self.NETWORK_VALIDATORS_TABLE} '
                ' VALUES(:public_key, :block_number) ON CONFLICT DO NOTHING',
                [
                    {'public_key': val.public_key, 'block_number': val.block_number}
                    for val in validators
                ],
            )

    def get_last_network_validator(self) -> NetworkValidator | None:
        """Fetches last network validator."""
        network_validators_table = self.NETWORK_VALIDATORS_TABLE
        with db_client.get_db_connection() as conn:
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
        with db_client.get_db_connection() as conn:
            res = conn.execute(
                f'SELECT public_key FROM {network_validators_table} WHERE (public_key = ?)',
                (public_key,),
            )
            return res.fetchone() is not None

    def get_next_validator_index(self, latest_public_keys: list[HexStr]) -> int:
        """Retrieves the index for the next validator."""
        with db_client.get_db_connection() as conn:
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
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                        CREATE TABLE IF NOT EXISTS {self.NETWORK_VALIDATORS_TABLE} (
                            public_key VARCHAR(98) UNIQUE NOT NULL,
                            block_number INTEGER NOT NULL
                        )
                        """
            )


class CheckpointCrud:
    CHECKPOINT_VALIDATORS = 'checkpoint_validators'

    @property
    def CHECKPOINTS_TABLE(self) -> str:
        return f'{settings.network}_checkpoints'

    def get_validators_checkpoint(self) -> BlockNumber | None:
        with db_client.get_db_connection() as conn:
            result = conn.execute(
                f'SELECT block FROM {self.CHECKPOINTS_TABLE}' ' WHERE name = :name',
                {'name': self.CHECKPOINT_VALIDATORS},
            ).fetchone()
            return BlockNumber(result[0]) if result else None

    def update_validators_checkpoint(self, block_number: BlockNumber) -> None:
        with db_client.get_db_connection() as conn:
            conn.execute(
                f'''INSERT INTO {self.CHECKPOINTS_TABLE} (name, block)
                    VALUES (:name, :block)
                    ON CONFLICT(name) DO UPDATE SET block = :block''',
                {'name': self.CHECKPOINT_VALIDATORS, 'block': block_number},
            )

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
                    f'INSERT INTO {self.CHECKPOINTS_TABLE} VALUES (?, ?)',
                    (self.CHECKPOINT_VALIDATORS, row[0]),
                )

    def _create_table(self, conn: Connection) -> None:
        conn.execute(
            f"""CREATE TABLE IF NOT EXISTS {self.CHECKPOINTS_TABLE} (
                    name TEXT NOT NULL UNIQUE,
                    block INTEGER NOT NULL
                )"""
        )

    def setup(self) -> None:
        """Creates tables and migrates from old schema if needed."""
        self._migrate()
        with db_client.get_db_connection() as conn:
            self._create_table(conn)
            conn.execute(
                f'INSERT INTO {self.CHECKPOINTS_TABLE} '
                ' VALUES(:name, :block) ON CONFLICT DO NOTHING',
                {
                    'name': self.CHECKPOINT_VALIDATORS,
                    'block': settings.network_config.KEEPER_GENESIS_BLOCK,
                },
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
