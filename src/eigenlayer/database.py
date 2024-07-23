import logging

from web3.types import BlockNumber

from src.common.clients import db_client
from src.config.settings import settings

logger = logging.getLogger(__name__)


class CheckpointType:
    PARTIAL = 'partial'
    COMPLETED = 'completed'


class CheckpointsCrud:
    def get_checkpoint_block_number(self, checkpoint_type: str) -> BlockNumber | None:
        with db_client.get_db_connection() as conn:
            res = conn.execute(
                f'SELECT value FROM {self.TABLE} WHERE checkpoint_type = ? ', (checkpoint_type,)
            ).fetchone()
            if res:
                return BlockNumber(res[0])
            return None

    def update_checkpoint_block_number(
        self, checkpoint_type: str, block_number: BlockNumber
    ) -> None:
        with db_client.get_db_connection() as conn:
            conn.execut(
                f'INSERT INTO {self.TABLE} '
                'VALUES (:checkpoint_type, :value) '
                'ON CONFLICT (checkpoint_type) DO UPDATE '
                'SET value = :value',
                (checkpoint_type, block_number),
            )

    def setup(self) -> None:
        """Creates tables."""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f'''
                    CREATE TABLE IF NOT EXISTS {self.TABLE} (
                        checkpoint_type VARCHAR(64) NOT NULL UNIQUE,
                        value INTEGER NOT NULL
                    )
                '''
            )

    @property
    def TABLE(self) -> str:
        return f'{settings.network}_withdrawal_checkpoints'
