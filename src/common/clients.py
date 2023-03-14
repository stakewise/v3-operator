import sqlite3
from pathlib import Path

from sw_utils import (
    IpfsFetchClient,
    construct_async_sign_and_send_raw_middleware,
    get_consensus_client,
    get_execution_client,
)
from sw_utils.decorators import backoff_requests_errors
from web3 import Web3

from src.common.accounts import operator_account
from src.config.settings import (
    CONSENSUS_ENDPOINT,
    DATABASE,
    DEFAULT_RETRY_TIME,
    EXECUTION_ENDPOINT,
    IPFS_FETCH_ENDPOINTS,
)


class Database:
    def get_db_connection(self):
        return sqlite3.connect(DATABASE)

    def create_db_dir(self):
        Path(DATABASE).parent.mkdir(parents=True, exist_ok=True)


def build_execution_client() -> Web3:
    w3 = get_execution_client(EXECUTION_ENDPOINT)
    w3.middleware_onion.add(construct_async_sign_and_send_raw_middleware(operator_account))
    w3.eth.default_account = operator_account.address
    return w3


class IpfsFetchRetryClient(IpfsFetchClient):
    @backoff_requests_errors(max_time=DEFAULT_RETRY_TIME)
    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        return await super().fetch_bytes(ipfs_hash)

    @backoff_requests_errors(max_time=DEFAULT_RETRY_TIME)
    async def fetch_json(self, ipfs_hash: str) -> dict | list:
        return await super().fetch_json(ipfs_hash)


execution_client = build_execution_client()
consensus_client = get_consensus_client(CONSENSUS_ENDPOINT)
db_client = Database()
ipfs_fetch_client = IpfsFetchRetryClient(IPFS_FETCH_ENDPOINTS)
