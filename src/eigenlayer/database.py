import logging

from src.common.clients import db_client
from src.config.settings import settings
from src.eigenlayer.typings import QueuedWithdrawal

logger = logging.getLogger(__name__)


class WithdrawalsCrud:
    @property
    def WITHDRAWALS_TABLE(self) -> str:
        return f'{settings.network}_withdrawals'

    def save_queued_withdrawals(self, queued_withdrawals: list[QueuedWithdrawal]) -> None:
        """Saves ."""
        with db_client.get_db_connection() as conn:
            conn.executemany(
                f'INSERT INTO {self.WITHDRAWALS_TABLE} '
                ' VALUES(:withdrawals_root, :block_number) ON CONFLICT DO NOTHING',
                [(w.withdrawal_root, w.block_number) for w in queued_withdrawals],
            )

    def get_last_queued_withdrawals(self) -> QueuedWithdrawal | None:
        """"""
        with db_client.get_db_connection() as conn:
            res = conn.execute(
                f'''SELECT block_number
                    FROM {self.WITHDRAWALS_TABLE} ORDER BY block_number DESC LIMIT 1'''
            ).fetchone()
            if res:
                return QueuedWithdrawal(public_key=res[0], block_number=res[1])
            return None

    def get_last_completed_withdrawals(self) -> QueuedWithdrawal | None:
        """"""
        with db_client.get_db_connection() as conn:
            res = conn.execute(
                f'''SELECT public_key, block_number
                    FROM {self.WITHDRAWALS_TABLE} ORDER BY block_number DESC LIMIT 1'''
            ).fetchone()
            if res:
                return QueuedWithdrawal(public_key=res[0], block_number=res[1])
            return None

    def get_queued_withdrawals(self) -> list[QueuedWithdrawal]:
        """"""
        with db_client.get_db_connection() as conn:
            res = conn.execute(
                f'''SELECT withdrawals_root, block_number
                    FROM {self.WITHDRAWALS_TABLE}
                    ORDER BY block_number'''
            ).fetchone()
            if res:
                return QueuedWithdrawal(public_key=res[0], block_number=res[1])
            return None

    def get_uncomplited_withdrawals(self) -> list[QueuedWithdrawal]:
        """"""
        with db_client.get_db_connection() as conn:
            res = conn.execute(
                f'''SELECT withdrawals_root, block_number
                    FROM {self.WITHDRAWALS_TABLE}
                    WHERE s_completed = FALSE
                    ORDER BY block_number'''
            ).fetchone()
            if res:
                return QueuedWithdrawal(public_key=res[0], block_number=res[1])
            return None

    def mask_as_completed(self, withdrawal_roots: list[str]) -> None:
        """"""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f'''UPDATE {self.NETWORK_VALIDATORS_TABLE}
                    SET is_completed = TRUE
                    WHERE withdrawals_root IN ({",".join(["?"] * len(withdrawal_roots))})''',
                withdrawal_roots,
            )

    def setup(self) -> None:
        """Creates tables."""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                    CREATE TABLE IF NOT EXISTS {self.WITHDRAWALS_TABLE} (
                        withdrawals_root VARCHAR(98) UNIQUE NOT NULL,
                        block_number INTEGER NOT NULL,
                        is_completed BOOLEAN FALSE

                    )
                """
            )
