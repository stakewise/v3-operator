import logging

from eth_typing import HexStr

from src.common.clients import db_client
from src.config.settings import NETWORK
from src.validators.typings import NetworkValidator

NETWORK_VALIDATORS_TABLE = f'{NETWORK}_network_validators'

logger = logging.getLogger(__name__)


def save_network_validators(validators: list[NetworkValidator]) -> None:
    """Saves network validators."""
    with db_client.get_db_connection() as conn:
        conn.executemany(
            f'INSERT INTO {NETWORK_VALIDATORS_TABLE} '
            ' VALUES(:public_key, :block_number) ON CONFLICT DO NOTHING',
            [(val.public_key, val.block_number) for val in validators],
        )


def get_last_network_validator() -> NetworkValidator | None:
    """Fetches last network validator."""
    with db_client.get_db_connection() as conn:
        res = conn.execute(
            f'''SELECT public_key, block_number
                FROM {NETWORK_VALIDATORS_TABLE} ORDER BY block_number DESC LIMIT 1'''
        ).fetchone()
        if res:
            return NetworkValidator(public_key=res[0], block_number=res[1])
        return None


def is_validator_registered(public_key: HexStr) -> bool:
    """Checks whether validator is registered."""
    with db_client.get_db_connection() as conn:
        res = conn.execute(
            f'SELECT public_key FROM {NETWORK_VALIDATORS_TABLE} WHERE (public_key = ?)',
            (public_key,),
        )
        return res.fetchone() is not None


def get_next_validator_index(latest_public_keys: list[HexStr]) -> int:
    """Retrieves the index for the next validator."""
    with db_client.get_db_connection() as conn:
        if latest_public_keys:
            cur = conn.execute(
                f'''SELECT COUNT(*) FROM {NETWORK_VALIDATORS_TABLE}
                    WHERE public_key NOT IN ({",".join(["?"] * len(latest_public_keys))})''',
                latest_public_keys,
            )
        else:
            cur = conn.execute(f'SELECT COUNT(*) FROM {NETWORK_VALIDATORS_TABLE}')

        index = cur.fetchone()[0]

    return index + len(latest_public_keys)


def setup() -> None:
    """Creates tables."""
    with db_client.get_db_connection() as conn:
        conn.execute(
            f"""
                    CREATE TABLE IF NOT EXISTS {NETWORK_VALIDATORS_TABLE} (
                        public_key VARCHAR(98) UNIQUE NOT NULL,
                        block_number INTEGER NOT NULL
                    )
                    """
        )
