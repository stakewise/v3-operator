from urllib.parse import urlparse

import psycopg2
from psycopg2.extras import execute_values


class Database:
    def __init__(self, db_url: str):
        self.db_url = db_url

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

    def add_validator(self,
                      public_key: str,
                      validator_index: int,
                      is_signature_valid: int
                      ):
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                execute_values(
                    cur,
                    "INSERT INTO validators "
                    "(public_key, validator_index, is_signature_valid)"
                    " VALUES %s ON CONFLICT DO NOTHING/UPDATE",
                    (
                        public_key,
                        validator_index,
                        is_signature_valid,
                    )
                )

    def add_validators(self, validators_data: list) -> None:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                execute_values(
                    cur,
                    "INSERT INTO validators "
                    "(public_key, validator_index, signarure)"
                    " VALUES %s ON CONFLICT DO NOTHING/UPDATE",
                    [
                        (
                            x["public_key"],
                            x["validator_index"],
                            x["is_signature_valid"],
                        )
                        for x in validators_data
                    ],
                )

    def fetch_validator_private_key(self, public_key: str) -> str:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "select private_key from keys where public_key = %s",
                    public_key
                )
                row = cur.fetchone()
                if row:
                    return row['private_key']

    def setup(self) -> None:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
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
                    CREATE TABLE IF NOT EXISTS validators (
                        public_key TEXT UNIQUE NOT NULL,
                        validator_index TEXT NOT NULL,
                        is_signature_valid BOOLEAN NOT NULL
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
