import sqlite3
from functools import cached_property
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

from src.common.wallet import hot_wallet
from src.config.settings import DEFAULT_RETRY_TIME, settings


class Database:
    def get_db_connection(self):
        return sqlite3.connect(settings.DATABASE)

    def create_db_dir(self):
        Path(settings.DATABASE).parent.mkdir(parents=True, exist_ok=True)


class ExecutionClient:
    @cached_property
    def client(self) -> Web3:
        w3 = get_execution_client(settings.EXECUTION_ENDPOINT)
        # Account is required when emitting transactions.
        # For read-only queries account may be omitted.
        w3.middleware_onion.add(construct_async_sign_and_send_raw_middleware(hot_wallet.account))
        w3.eth.default_account = hot_wallet.address
        return w3

    def __getattr__(self, item):
        return getattr(self.client, item)


class ReadOnlyExecutionClient:
    @cached_property
    def client(self) -> Web3:
        w3 = get_execution_client(settings.EXECUTION_ENDPOINT)
        return w3

    def __getattr__(self, item):
        return getattr(self.client, item)


class ConsensusClient:
    @cached_property
    def client(self) -> ExtendedAsyncBeacon:
        return get_consensus_client(settings.CONSENSUS_ENDPOINT)

    def __getattr__(self, item):
        return getattr(self.client, item)


class IpfsFetchRetryClient:
    @cached_property
    def client(self) -> IpfsFetchClient:
        return IpfsFetchClient(endpoints=settings.IPFS_FETCH_ENDPOINTS)

    @backoff.on_exception(backoff.expo, IpfsException, max_time=DEFAULT_RETRY_TIME)
    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        return await self.client.fetch_bytes(ipfs_hash)

    @backoff.on_exception(backoff.expo, IpfsException, max_time=DEFAULT_RETRY_TIME)
    async def fetch_json(self, ipfs_hash: str) -> dict | list:
        return await self.client.fetch_json(ipfs_hash)


db_client = Database()
execution_client = ExecutionClient()
read_only_execution_client = ReadOnlyExecutionClient()
consensus_client = ConsensusClient()
ipfs_fetch_client = IpfsFetchRetryClient()
