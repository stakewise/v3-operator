import sqlite3
from pathlib import Path

import backoff
from sw_utils import (
    ExtendedAsyncBeacon,
    IpfsException,
    IpfsFetchClient,
    construct_async_sign_and_send_raw_middleware,
    get_consensus_client,
    get_execution_client,
)
from web3 import Web3

from src.common.accounts import OperatorAccount
from src.config.settings import DEFAULT_RETRY_TIME, settings


class Database:
    def get_db_connection(self):
        return sqlite3.connect(settings.DATABASE)

    def create_db_dir(self):
        Path(settings.DATABASE).parent.mkdir(parents=True, exist_ok=True)


class ExecutionClient:
    @property
    def client(self) -> Web3:
        operator_account = OperatorAccount().operator_account
        w3 = get_execution_client(settings.EXECUTION_ENDPOINT)
        w3.middleware_onion.add(construct_async_sign_and_send_raw_middleware(operator_account))
        w3.eth.default_account = operator_account.address
        return w3


class ConsensusClient:
    @property
    def client(self) -> ExtendedAsyncBeacon:
        return get_consensus_client(settings.CONSENSUS_ENDPOINT)


class IpfsFetchRetryClient(IpfsFetchClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, endpoints=settings.IPFS_FETCH_ENDPOINTS)

    @backoff.on_exception(backoff.expo, IpfsException, max_time=DEFAULT_RETRY_TIME)
    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        return await super().fetch_bytes(ipfs_hash)

    @backoff.on_exception(backoff.expo, IpfsException, max_time=DEFAULT_RETRY_TIME)
    async def fetch_json(self, ipfs_hash: str) -> dict | list:
        return await super().fetch_json(ipfs_hash)


db_client = Database()
