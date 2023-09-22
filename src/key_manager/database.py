import click
from eth_typing import HexStr

try:
    import psycopg2
    from psycopg2.extras import execute_values
except ImportError:
    pass

from src.key_manager.typings import DatabaseConfigRecord, DatabaseKeyRecord


class Database:
    def __init__(self, db_url: str):
        self.db_url = db_url

    def upload_keys(self, keys: list[DatabaseKeyRecord]) -> None:
        """Updates database records to new state."""
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                # recreate table
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS keys (
                        public_key TEXT UNIQUE NOT NULL,
                        private_key TEXT UNIQUE NOT NULL,
                        nonce TEXT NOT NULL
                    );
                    """
                )

                # insert keys
                execute_values(
                    cur,
                    'INSERT INTO keys (public_key, private_key, nonce) '
                    'VALUES %s ON CONFLICT DO NOTHING',
                    [
                        (
                            x.public_key,
                            x.private_key,
                            x.nonce,
                        )
                        for x in keys
                    ],
                )

    def upload_configs(self, configs: list[DatabaseConfigRecord]) -> None:
        """Updates database records to new state."""
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                # recreate table
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS configs (
                        id SERIAL PRIMARY KEY,
                        name TEXT UNIQUE NOT NULL,
                        data TEXT NOT NULL
                    );
                    """
                )

                # insert keys
                execute_values(
                    cur,
                    'INSERT INTO configs (name, data) '
                    'VALUES %s '
                    'ON CONFLICT (name) '
                    'DO UPDATE SET data = EXCLUDED.data;',
                    [
                        (
                            x.name,
                            x.data,
                        )
                        for x in configs
                    ],
                )

    def fetch_public_keys_by_range(self, start_index: int, end_index: int) -> list[HexStr]:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT public_key FROM keys ORDER BY public_key LIMIT %s OFFSET %s;',
                    (end_index - start_index, start_index),
                )
                rows = cur.fetchall()
                return [row[0] for row in rows]

    def fetch_public_keys_count(self) -> int:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    'SELECT COUNT(public_key) FROM keys',
                )
                row = cur.fetchone()
                return row[0]

    def fetch_keys(self) -> list[DatabaseKeyRecord]:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT * FROM keys ORDER BY public_key')
                rows = cur.fetchall()
                return [
                    DatabaseKeyRecord(
                        public_key=row[0],
                        private_key=row[1],
                        nonce=row[2],
                    )
                    for row in rows
                ]

    def fetch_configs(self) -> list[DatabaseConfigRecord]:
        with _get_db_connection(self.db_url) as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT * FROM configs')
                rows = cur.fetchall()
                return [
                    DatabaseConfigRecord(
                        name=row[1],
                        data=row[2],
                    )
                    for row in rows
                ]


def check_db_connection(db_url):
    connection = _get_db_connection(db_url=db_url)
    try:
        cur = connection.cursor()
        cur.execute('SELECT 1')
    except psycopg2.OperationalError as e:
        raise click.ClickException(
            f'Error: failed to connect to the database server with provided URL. '
            f'Error details: {e}',
        )


def _get_db_connection(db_url):
    return psycopg2.connect(dsn=db_url)
