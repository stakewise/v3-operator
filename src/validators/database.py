import logging

from eth_typing import HexStr
from psycopg.rows import class_row
from psycopg.sql import SQL, Identifier

from src.common.clients import db_client
from src.config.settings import NETWORK
from src.validators.typings import NetworkValidator

NETWORK_VALIDATORS_TABLE = f'{NETWORK}_network_validators'

logger = logging.getLogger(__name__)


def save_network_validators(validators: list[NetworkValidator]) -> None:
    """Saves network validators."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                SQL(
                    'INSERT INTO {} (public_key, block_number)'
                    ' VALUES (%s, %s) ON CONFLICT DO NOTHING'
                ).format(Identifier(NETWORK_VALIDATORS_TABLE)),
                [(val.public_key, val.block_number) for val in validators],
            )


def get_last_network_validator() -> NetworkValidator | None:
    """Fetches last network validator."""
    with db_client.get_db_connection() as conn:
        with conn.cursor(row_factory=class_row(NetworkValidator)) as cur:
            cur.execute(
                SQL('SELECT * FROM {} ORDER BY block_number DESC LIMIT 1').format(
                    Identifier(NETWORK_VALIDATORS_TABLE),
                )
            )
            return cur.fetchone()


def is_validator_registered(public_key: HexStr) -> bool:
    """Checks whether validator is registered."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                SQL('SELECT public_key FROM {} WHERE (public_key = %s)').format(
                    Identifier(NETWORK_VALIDATORS_TABLE),
                ),
                (public_key,),
            )
            return cur.fetchone() is not None


def get_next_validator_index(latest_public_keys: list[HexStr]) -> int:
    """Retrieves the index for the next validator."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            if latest_public_keys:
                cur.execute(
                    SQL('SELECT COUNT(*) FROM {} WHERE NOT (public_key = ANY(%s))').format(
                        Identifier(NETWORK_VALIDATORS_TABLE),
                    ),
                    (latest_public_keys,),
                )
            else:
                cur.execute(
                    SQL('SELECT COUNT(*) FROM {}').format(
                        Identifier(NETWORK_VALIDATORS_TABLE),
                    )
                )
            index = cur.fetchone()[0]

    return index + len(latest_public_keys)


def setup() -> None:
    """Creates tables."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {} (
                        public_key VARCHAR(98) UNIQUE NOT NULL,
                        block_number INTEGER NOT NULL
                    )
                    """
                ).format(Identifier(NETWORK_VALIDATORS_TABLE)),
            )
