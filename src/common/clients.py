import sqlite3

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
    DATABASE,
    EXECUTION_ENDPOINT,
    IPFS_FETCH_ENDPOINTS,
)


class Database:
    def get_db_connection(self):
        return sqlite3.connect(DATABASE)


def build_execution_client() -> Web3:
    w3 = get_execution_client(EXECUTION_ENDPOINT)
    w3.middleware_onion.add(construct_async_sign_and_send_raw_middleware(operator_account))
    w3.eth.default_account = operator_account.address
    return w3


execution_client = build_execution_client()
consensus_client = get_consensus_client(CONSENSUS_ENDPOINT)
db_client = Database()
ipfs_fetch_client = IpfsFetchClient(IPFS_FETCH_ENDPOINTS)
