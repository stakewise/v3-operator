import logging

from web3.types import BlockNumber

from src.common.clients import db_client
from src.config.settings import settings

logger = logging.getLogger(__name__)


class WithdrawalCheckpointsCrud:
    def get_last_completed_withdrawals_block_number(self) -> BlockNumber | None:
        with db_client.get_db_connection() as conn:
            res = conn.execute(f'''SELECT block_number FROM {self.TABLE}''').fetchone()
            if res:
                return BlockNumber(res[0])
            return None

    def save_last_completed_withdrawals_block_number(self, block_number: BlockNumber) -> None:
        """Saves ."""
        with db_client.get_db_connection() as conn:
            conn.execut(f'DELETE FROM {self.TABLE}')
            conn.execute(
                f'INSERT INTO {self.TABLE} VALUES (:block_number)',
                block_number,
            )

    def setup(self) -> None:
        """Creates tables."""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                    CREATE TABLE IF NOT EXISTS {self.TABLE} (
                        block_number INTEGER NOT NULL
                    )
                """
            )

    @property
    def TABLE(self) -> str:
        return f'{settings.network}_withdrawal_checkpoints'
