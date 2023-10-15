import json

import click
from eth_typing import HexStr

from src.config.settings import settings
from src.remote_db.typings import RemoteDatabaseKeyPair


def get_db_connection(db_url):
    import psycopg2  # pylint: disable=import-outside-toplevel

    return psycopg2.connect(dsn=db_url)


def check_db_connection(db_url: str):
    import psycopg2  # pylint: disable=import-outside-toplevel

    try:
        with get_db_connection(db_url) as conn:
            cur = conn.cursor()
            cur.execute('SELECT 1')
    except psycopg2.OperationalError as e:
        raise click.ClickException(
            f'Error: failed to connect to the database server with provided URL.\n' f'Details: {e}',
        )


class KeyPairsCrud:
    def __init__(self, db_connection=None, db_url: str | None = None):
        self.db_connection = db_connection or get_db_connection(db_url)

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
                    SELECT parent_public_key, public_key, private_key, nonce
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
                parent_public_key=row[0],
                public_key=row[1],
                private_key=row[2],
                nonce=row[3],
            )

    def get_keypairs(
        self, has_parent_public_key: bool | None = None
    ) -> list[RemoteDatabaseKeyPair]:
        """Returns keypairs from the database."""
        where_list = []
        params: dict = {}

        if has_parent_public_key is True:
            where_list.append('parent_public_key IS NOT NULL')
        elif has_parent_public_key is False:
            where_list.append('parent_public_key IS NULL')

        query = f'''
                SELECT parent_public_key, public_key, private_key, nonce
                FROM {self.table}
        '''

        if where_list:
            query += f'WHERE {" AND ".join(where_list)}\n'

        query += 'ORDER BY public_key'

        with self.db_connection.cursor() as cur:
            cur.execute(query, params)
            res = cur.fetchall()

        return [
            RemoteDatabaseKeyPair(
                vault=settings.vault,
                parent_public_key=row[0],
                public_key=row[1],
                private_key=row[2],
                nonce=row[3],
            )
            for row in res
        ]

    def remove_keypairs(self, in_parent_public_keys: set[HexStr] | None = None) -> None:
        """Removes keypairs from the database."""
        where_list = ['vault = %(vault)s']
        params: dict = {'vault': settings.vault}

        if in_parent_public_keys is not None:
            where_list.append('parent_public_key IN %(in_parent_public_keys)s')
            params['in_parent_public_keys'] = tuple(in_parent_public_keys)

        query = f'''
                DELETE FROM {self.table}
        '''
        query += f'WHERE {" AND ".join(where_list)}\n'

        with self.db_connection.cursor() as cur:
            cur.execute(query, params)

    def upload_keypairs(self, keypairs: list[RemoteDatabaseKeyPair]) -> None:
        """Uploads keypairs to the database."""
        with self.db_connection.cursor() as cur:
            cur.executemany(
                f'''
                    INSERT INTO {self.table} (
                        vault,
                        parent_public_key,
                        public_key,
                        private_key,
                        nonce
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                ''',
                [
                    (
                        keypair.vault,
                        keypair.parent_public_key,
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
                        parent_public_key VARCHAR(98),
                        public_key VARCHAR(98) UNIQUE NOT NULL,
                        private_key VARCHAR(66) UNIQUE NOT NULL,
                        nonce VARCHAR(34) UNIQUE NOT NULL
                    )
                '''
            )


class ConfigsCrud:
    remote_signer_config_name = 'remote_signer_config.json'

    def __init__(self, db_connection=None, db_url: str | None = None):
        self.db_connection = db_connection or get_db_connection(db_url)

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

    def get_remote_signer_config(self) -> dict | None:
        """Returns the remote signer config from the database."""
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'SELECT data FROM {self.table} WHERE vault = %s AND name = %s',
                (settings.vault, self.remote_signer_config_name),
            )
            row = cur.fetchone()
            if row is None:
                return None
            return json.loads(row[0])

    def update_remote_signer_config(self, data: dict) -> None:
        """Updates the remote signer config in the database."""
        data_string = json.dumps(data)
        with self.db_connection.cursor() as cur:
            cur.execute(
                f'''
                    INSERT INTO {self.table} (vault, name, data)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (vault, name) DO UPDATE SET data = %s
                ''',
                (settings.vault, self.remote_signer_config_name, data_string, data_string),
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
