import logging
import sqlite3
from functools import cached_property
from typing import cast

from sw_utils import (
    ExtendedAsyncBeacon,
    IpfsFetchClient,
    construct_async_sign_and_send_raw_middleware,
    get_consensus_client,
    get_execution_client,
)
from sw_utils.decorators import retry_ipfs_exception
from web3 import AsyncWeb3

from src.common.wallet import hot_wallet
from src.config.settings import DEFAULT_RETRY_TIME, settings

logger = logging.getLogger(__name__)


class Database:
    def get_db_connection(self):
        return sqlite3.connect(settings.database)

    def create_db_dir(self):
        settings.database.parent.mkdir(parents=True, exist_ok=True)


class ExecutionClient:
    @cached_property
    def client(self) -> AsyncWeb3:
        w3 = get_execution_client(settings.execution_endpoints, retry_timeout=DEFAULT_RETRY_TIME)
        # Account is required when emitting transactions.
        # For read-only queries account may be omitted.
        if hot_wallet.can_load():
            w3.middleware_onion.add(
                construct_async_sign_and_send_raw_middleware(hot_wallet.account)
            )
            w3.eth.default_account = hot_wallet.address
        else:
            logger.warning('Unable to load hot wallet')

        return w3

    def __getattr__(self, item):
        return getattr(self.client, item)


class ConsensusClient:
    @cached_property
    def client(self) -> ExtendedAsyncBeacon:
        return get_consensus_client(settings.consensus_endpoints, retry_timeout=DEFAULT_RETRY_TIME)

    def __getattr__(self, item):
        return getattr(self.client, item)


class IpfsFetchRetryClient:
    @cached_property
    def client(self) -> IpfsFetchClient:
        return IpfsFetchClient(endpoints=settings.ipfs_fetch_endpoints)

    @retry_ipfs_exception(delay=DEFAULT_RETRY_TIME)
    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        return await self.client.fetch_bytes(ipfs_hash)

    @retry_ipfs_exception(delay=DEFAULT_RETRY_TIME)
    async def fetch_json(self, ipfs_hash: str) -> dict | list:
        return await self.client.fetch_json(ipfs_hash)


db_client = Database()
execution_client = cast(AsyncWeb3, ExecutionClient())
consensus_client = cast(ExtendedAsyncBeacon, ConsensusClient())
ipfs_fetch_client = IpfsFetchRetryClient()
