import psycopg
from sw_utils import IpfsFetchClient, get_execution_client

from src.config.settings import (
    EXECUTION_ENDPOINT,
    IPFS_FETCH_ENDPOINTS,
    POSTGRES_DB,
    POSTGRES_HOSTNAME,
    POSTGRES_PASSWORD,
    POSTGRES_PORT,
    POSTGRES_USER,
)


class Database:
    def __init__(self):
        self.connection_args = dict(
            dbname=POSTGRES_DB,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            host=POSTGRES_HOSTNAME,
            port=POSTGRES_PORT,
        )

    def get_db_connection(self):
        return psycopg.connect(**self.connection_args)


execution_client = get_execution_client(EXECUTION_ENDPOINT)
db_client = Database()
ipfs_fetch_client = IpfsFetchClient(IPFS_FETCH_ENDPOINTS)
