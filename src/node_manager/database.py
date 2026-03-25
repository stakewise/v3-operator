from eth_typing import BlockNumber, HexStr

from src.common.clients import db_client
from src.config.settings import settings
from src.validators.typings import VaultValidator

CHECKPOINT_OPERATOR_VALIDATORS = 'checkpoint_operator_validators'


class OperatorValidatorCrud:
    """CRUD for operator-specific validators tracked from NodesManager events."""

    @property
    def OPERATOR_VALIDATORS_TABLE(self) -> str:
        return f'{settings.network}_operator_validators'

    @property
    def CHECKPOINTS_TABLE(self) -> str:
        return f'{settings.network}_checkpoints'

    def save_operator_validators(self, validators: list[VaultValidator]) -> None:
        with db_client.get_db_connection() as conn:
            conn.executemany(
                f'INSERT INTO {self.OPERATOR_VALIDATORS_TABLE} '
                ' VALUES(:public_key, :block_number) ON CONFLICT DO NOTHING',
                [
                    {'public_key': val.public_key, 'block_number': val.block_number}
                    for val in validators
                ],
            )

    def get_operator_public_keys(self) -> set[HexStr]:
        with db_client.get_db_connection() as conn:
            results = conn.execute(
                f'SELECT public_key FROM {self.OPERATOR_VALIDATORS_TABLE}',
            ).fetchall()
            return {res[0] for res in results}

    def get_checkpoint(self) -> BlockNumber | None:
        with db_client.get_db_connection() as conn:
            result = conn.execute(
                f'SELECT block FROM {self.CHECKPOINTS_TABLE} WHERE name = :name',
                {'name': CHECKPOINT_OPERATOR_VALIDATORS},
            ).fetchone()
            return BlockNumber(result[0]) if result else None

    def update_checkpoint(self, block_number: BlockNumber) -> None:
        with db_client.get_db_connection() as conn:
            conn.execute(
                f'''INSERT INTO {self.CHECKPOINTS_TABLE} (name, block)
                    VALUES (:name, :block)
                    ON CONFLICT(name) DO UPDATE SET block = :block''',
                {'name': CHECKPOINT_OPERATOR_VALIDATORS, 'block': block_number},
            )

    def setup(self) -> None:
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.OPERATOR_VALIDATORS_TABLE} (
                    public_key VARCHAR(98) UNIQUE NOT NULL,
                    block_number INTEGER NOT NULL
                )
                """
            )
