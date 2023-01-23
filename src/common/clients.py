import psycopg
from sw_utils import (
    IpfsFetchClient,
    construct_async_sign_and_send_raw_middleware,
    get_consensus_client,
    get_execution_client,
)
from web3 import Web3

from src.common.accounts import operator_account
from src.config.settings import (
    CONSENSUS_ENDPOINT,
    EXECUTION_ENDPOINT,
    IPFS_FETCH_ENDPOINTS,
    POSTGRES_DB,
    POSTGRES_HOST,
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
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
        )

    def get_db_connection(self):
        return psycopg.connect(**self.connection_args)


def build_execution_client() -> Web3:
    w3 = get_execution_client(EXECUTION_ENDPOINT)
    w3.middleware_onion.add(construct_async_sign_and_send_raw_middleware(operator_account))
    w3.eth.default_account = operator_account.address
    return w3


execution_client = build_execution_client()
consensus_client = get_consensus_client(CONSENSUS_ENDPOINT)
db_client = Database()
ipfs_fetch_client = IpfsFetchClient(IPFS_FETCH_ENDPOINTS)
