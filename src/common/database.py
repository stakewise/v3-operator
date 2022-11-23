from typing import Union
from urllib.parse import urlparse

import psycopg2
from psycopg2.extras import execute_values

# todo: Network?


class Database:
    def __init__(self, db_url: str):
        self.db_url = db_url

    # blocks
    def save_block(self, block_number) -> None:
        """"""
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                execute_values(
                    cur,
                    "DELETE from scanned_blocks; "
                    "INSERT INTO scanned_blocks (block_number) VALUES %s",
                    [(block_number,)],
                )

    def get_last_block(self) -> Union[int, None]:
        """"""
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select block_number from scanned_blocks LIMIT 1",
                )
                row = cur.fetchone()
                if row:
                    return row["block_number"]

    # deposit events
    def check_public_key(self, public_key: str) -> bool:
        """Check that public key is not used be beacon chain already."""
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select public_key from validators where public_key= %s",
                    (public_key,),
                )
                rows = cur.fetchall()
                return bool(rows)

    def create_deposit_event(
        self,
        public_key: str,
        signature: str,
        index: int,
        log_index: int,
        transaction_hash: str,
        block_number: int,
    ):
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                execute_values(
                    cur,
                    "INSERT INTO deposit_events "
                    "(public_key, signature, index, log_index, transaction_hash, block_number)"
                    " VALUES %s ON CONFLICT DO NOTHING",
                    [
                        (
                            public_key,
                            signature,
                            index,
                            log_index,
                            transaction_hash,
                            block_number,
                        )
                    ],
                )

    def delete_deposit_events(self, since_block):
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE from deposit_events where block_number >= %s",
                    (since_block,),
                )

    # keys
    def fetch_validator_private_key(self, public_key: str) -> str:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("select private_key from keys where public_key = %s", public_key)
                row = cur.fetchone()
                if row:
                    return row["private_key"]

    def setup(self) -> None:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS scanned_blocks (
                        block_number INT NOT NULL
                    );
                    """
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS keys (
                        public_key TEXT UNIQUE NOT NULL,
                        private_key TEXT UNIQUE NOT NULL,
                        nonce TEXT NOT NULL,
                        validator_index TEXT NOT NULL)
                    ;"""
                )

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS deposit_events (
                        public_key TEXT UNIQUE NOT NULL,
                        signature TEXT NOT NULL,
                        index NUMERIC NOT NULL,
                        block_number NUMERIC NOT NULL,
                        log_index NUMERIC NOT NULL,
                        transaction_hash TEXT NOT NULL,
                        validator_index NUMERIC DEFAULT NULL,
                        is_signature_valid BOOLEAN DEFAULT NULL
                        )
                    ;"""
                )


def check_db_connection(db_url):
    connection = _get_db_connection(db_url=db_url)
    cur = connection.cursor()
    cur.execute("SELECT 1")


def _get_db_connection(db_url):
    result = urlparse(db_url)
    return psycopg2.connect(
        database=result.path[1:],
        user=result.username,
        password=result.password,
        host=result.hostname,
        port=result.port,
    )
