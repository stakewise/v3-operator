import json
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
        """Returns the number of keypairs in the database."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'SELECT COUNT(*) FROM {self.table} WHERE vault = %s',
                (settings.vault,),
            )
            row = cur.fetchone()
            return row[0]

    def get_first_keypair(self) -> RemoteDatabaseKeyPair | None:
        """Returns the first keypair in the database."""
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
                vault=settings.vault,
                public_key=row[0],
                private_key=row[1],
                nonce=row[2],
            )

    def get_keypairs(self) -> list[RemoteDatabaseKeyPair]:
        """Returns keypairs from the database."""
        params: dict = {}

        query = f'''
                SELECT public_key, private_key, nonce
                FROM {self.table}
        '''

        query += 'ORDER BY public_key'

        with self.db_connection.cursor() as cur:
            cur.execute(query, params)
            res = cur.fetchall()

        return [
            RemoteDatabaseKeyPair(
                vault=settings.vault,
                public_key=row[0],
                private_key=row[1],
                nonce=row[2],
            )
            for row in res
        ]

    def remove_keypairs(self, in_public_keys: set[HexStr] | None = None) -> None:
        """Removes keypairs from the database."""
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
        """Uploads keypairs to the database."""
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
                        keypair.vault,
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
                        public_key VARCHAR(98) UNIQUE NOT NULL,
                        private_key VARCHAR(66) UNIQUE NOT NULL,
                        nonce VARCHAR(34) UNIQUE NOT NULL
                    )
                '''
            )


class ConfigsCrud:
    deposit_data_name = 'deposit_data.json'

    def __init__(self, db_connection: Any | None = None, db_url: str | None = None):
        if db_connection:
            self.db_connection = db_connection
        elif db_url:
            self.db_connection = get_db_connection(db_url)
        else:
            raise RuntimeError('db_connection or db_url must be set')

    @property
    def table(self) -> str:
        return f'{settings.network}_configs'

    def get_configs_count(self) -> int:
        """Returns the number of configs in the database."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'SELECT COUNT(*) FROM {self.table} WHERE vault = %s',
                (settings.vault,),
            )
            row = cur.fetchone()
            return row[0]

    def get_deposit_data(self) -> list | None:
        """Returns the deposit data from the database."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'SELECT data FROM {self.table} WHERE vault = %s AND name = %s',
                (settings.vault, self.deposit_data_name),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return json.loads(row[0])

    def update_deposit_data(self, deposit_data: list[dict]) -> None:
        """Updates the deposit data in the database."""
        data_string = json.dumps(deposit_data)
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'''
                    INSERT INTO {self.table} (vault, name, data)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (vault, name) DO UPDATE SET data = %s
                ''',
                (settings.vault, self.deposit_data_name, data_string, data_string),
            )

    def remove_configs(self) -> None:
        """Clean up configs for the vault."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'DELETE FROM {self.table} WHERE vault = %s',
                (settings.vault,),
            )

    def create_table(self) -> None:
        """Create table."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'''
                    CREATE TABLE IF NOT EXISTS {self.table} (
                        vault VARCHAR(42) NOT NULL,
                        name VARCHAR(25) NOT NULL,
                        data TEXT NOT NULL,
                        UNIQUE(vault, name)
                    )
                '''
            )


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
