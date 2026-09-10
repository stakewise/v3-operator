from typing import Any

import click
from eth_typing import HexStr

from src.config.settings import settings
from src.remote_db.typings import RemoteDatabaseKeyPair


class KeyPairsCrud:
    def __init__(self, db_connection: Any | None = None, db_url: str | None = None):
        if db_connection:
            self.db_connection = db_connection
        elif db_url:
            self.db_connection = get_db_connection(db_url)
        else:
            raise RuntimeError('db_connection or db_url must be set')

    @property
    def table(self) -> str:
        return f'{settings.network}_keypairs'

    def get_keypairs_count(self) -> int:
        """Returns the number of keypairs in the database for the current vault."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'SELECT COUNT(*) FROM {self.table} WHERE vault = %s',
                (settings.vault,),
            )
            row = cur.fetchone()
            return row[0]

    def get_first_keypair(self) -> RemoteDatabaseKeyPair | None:
        """Returns the first keypair in the database for the current vault."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'''
                    SELECT public_key, private_key, nonce
                    FROM {self.table}
                    WHERE vault = %s
                    ORDER BY public_key
                    LIMIT 1
                ''',
                (settings.vault,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return RemoteDatabaseKeyPair(
                public_key=row[0],
                private_key=row[1],
                nonce=row[2],
            )

    def get_keypairs(self) -> list[RemoteDatabaseKeyPair]:
        """Returns keypairs from the database for the current vault."""
        params: dict = {'vault': settings.vault}

        query = f'''
                SELECT public_key, private_key, nonce
                FROM {self.table}
                WHERE vault = %(vault)s
        '''

        query += ' ORDER BY public_key'

        with self.db_connection.cursor() as cur:
            cur.execute(query, params)
            res = cur.fetchall()

        return [
            RemoteDatabaseKeyPair(
                public_key=row[0],
                private_key=row[1],
                nonce=row[2],
            )
            for row in res
        ]

    def remove_keypairs(self, in_public_keys: set[HexStr] | None = None) -> None:
        """Removes keypairs from the database for the current vault."""
        where_list = ['vault = %(vault)s']
        params: dict = {'vault': settings.vault}

        if in_public_keys is not None:
            where_list.append('public_key IN %(in_public_keys)s')
            params['in_public_keys'] = tuple(in_public_keys)

        query = f'''
                DELETE FROM {self.table}
        '''
        query += f'WHERE {' AND '.join(where_list)}\n'

        with self.db_connection.cursor() as cur:
            cur.execute(query, params)

    def upload_keypairs(self, keypairs: list[RemoteDatabaseKeyPair]) -> None:
        """Uploads keypairs to the database for the current vault."""
        with self.db_connection.cursor() as cur:
            cur.executemany(
                f'''
                    INSERT INTO {self.table} (
                        vault,
                        public_key,
                        private_key,
                        nonce
                    )
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                ''',
                [
                    (
                        settings.vault,
                        keypair.public_key,
                        keypair.private_key,
                        keypair.nonce,
                    )
                    for keypair in keypairs
                ],
            )

    def create_table(self) -> None:
        """Create table."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'''
                    CREATE TABLE IF NOT EXISTS {self.table} (
                        vault VARCHAR(42) NOT NULL,
                        public_key VARCHAR(98) NOT NULL,
                        private_key VARCHAR(66) NOT NULL,
                        nonce VARCHAR(34) NOT NULL,
                        UNIQUE (vault, public_key)
                    )
                '''
            )
            # Upgrades a pre-existing V4-schema table (created without the
            # vault column) so it can be scoped per vault; a no-op otherwise.
            cur.execute(f'ALTER TABLE {self.table} ADD COLUMN IF NOT EXISTS vault VARCHAR(42)')


def check_db_connection(db_url: str) -> None:
    import psycopg2  # pylint: disable=import-outside-toplevel

    try:
        with get_db_connection(db_url) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1')
    except psycopg2.OperationalError as e:
        raise click.ClickException(
            f'Error: failed to connect to the database server with provided URL.\n' f'Details: {e}',
        )


def get_db_connection(db_url: str):  # type: ignore
    import psycopg2  # pylint: disable=import-outside-toplevel

    return psycopg2.connect(dsn=db_url)
