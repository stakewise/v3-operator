import logging

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
    @property
    def CHECKPOINTS_TABLE(self) -> str:
        return f'{settings.network}_checkpoints'

    def save_checkpoints(self) -> None:
        with db_client.get_db_connection() as conn:
            conn.execute(
                f'INSERT INTO {self.CHECKPOINTS_TABLE} '
                ' VALUES(:block_number,:block_number) ON CONFLICT DO NOTHING',
                {'block_number': settings.network_config.KEEPER_GENESIS_BLOCK},
            )

    def get_vault_validators_checkpoint(self) -> BlockNumber | None:
        with db_client.get_db_connection() as conn:
            results = conn.execute(
                f'''SELECT checkpoint_validators
                    FROM {self.CHECKPOINTS_TABLE}
                    ''',
            ).fetchone()
            return BlockNumber(results[0]) if results else None

    def get_vault_v2_validators_checkpoint(self) -> BlockNumber | None:
        with db_client.get_db_connection() as conn:
            results = conn.execute(
                f'''SELECT checkpoint_v2_validators
                    FROM {self.CHECKPOINTS_TABLE}
                    ''',
            ).fetchone()
            return BlockNumber(results[0]) if results else None

    def update_vault_checkpoints(self, block_number: BlockNumber) -> None:
        with db_client.get_db_connection() as conn:
            conn.execute(
                f'DELETE FROM {self.CHECKPOINTS_TABLE}',
            )
            conn.execute(
                f'''INSERT INTO {self.CHECKPOINTS_TABLE}
                   VALUES (:block_number, :block_number)
                    ''',
                {'block_number': block_number},
            )

    def setup(self) -> None:
        """Creates tables."""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                        CREATE TABLE IF NOT EXISTS {self.CHECKPOINTS_TABLE} (
                            checkpoint_validators INTEGER NOT NULL,
                            checkpoint_v2_validators INTEGER NOT NULL,
                            UNIQUE(checkpoint_validators, checkpoint_v2_validators)
                        )
                        """
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
