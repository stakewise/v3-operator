import logging
import sqlite3
from functools import cached_property
from sqlite3 import Connection
from typing import cast

from sw_utils import (
    ExtendedAsyncBeacon,
    IpfsFetchClient,
    get_consensus_client,
    get_execution_client,
)
from web3 import AsyncWeb3
from web3.middleware.signing import async_construct_sign_and_send_raw_middleware

from src.common.wallet import hot_wallet
from src.config.settings import settings

logger = logging.getLogger(__name__)


class Database:
    def get_db_connection(self) -> Connection:
        return sqlite3.connect(settings.database)

    def create_db_dir(self) -> None:
        settings.database.parent.mkdir(parents=True, exist_ok=True)


class ExecutionClient:
    client: AsyncWeb3
    is_set_up = False
    use_retries = True

    def __init__(self, use_retries: bool = True) -> None:
        self.use_retries = use_retries

    async def setup(self) -> None:
        if not any(settings.execution_endpoints):
            return

        retry_timeout = 0
        if self.use_retries:
            retry_timeout = settings.execution_retry_timeout

        w3 = get_execution_client(
            settings.execution_endpoints,
            timeout=settings.execution_timeout,
            retry_timeout=retry_timeout,
            jwt_secret=settings.execution_jwt_secret,
        )
        # Account is required when emitting transactions.
        # For read-only queries account may be omitted.
        if hot_wallet.can_load():
            w3.middleware_onion.add(
                await async_construct_sign_and_send_raw_middleware(hot_wallet.account)
            )
            w3.eth.default_account = hot_wallet.address

        self.client = w3
        self.is_set_up = True
        return None

    def __getattr__(self, item):  # type: ignore
        if not self.is_set_up:
            raise RuntimeError('Execution client is not ready. You need to call setup() method')
        return getattr(self.client, item)


class ConsensusClient:
    @cached_property
    def client(self) -> ExtendedAsyncBeacon:
        return get_consensus_client(
            settings.consensus_endpoints,
            timeout=settings.consensus_timeout,
            retry_timeout=settings.consensus_retry_timeout,
        )

    def __getattr__(self, item):  # type: ignore
        return getattr(self.client, item)


class IpfsLazyFetchClient:
    @cached_property
    def client(self) -> IpfsFetchClient:
        return IpfsFetchClient(
            ipfs_endpoints=settings.ipfs_fetch_endpoints,
            timeout=settings.ipfs_timeout,
            retry_timeout=settings.ipfs_retry_timeout,
        )

    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        return await self.client.fetch_bytes(ipfs_hash)

    async def fetch_json(self, ipfs_hash: str) -> dict | list:
        return await self.client.fetch_json(ipfs_hash)


db_client = Database()
execution_client = cast(AsyncWeb3, ExecutionClient())
execution_non_retry_client = cast(AsyncWeb3, ExecutionClient(use_retries=False))
consensus_client = cast(ExtendedAsyncBeacon, ConsensusClient())
ipfs_fetch_client = IpfsLazyFetchClient()


async def setup_clients() -> None:
    await execution_client.setup()  # type: ignore
    await execution_non_retry_client.setup()  # type: ignore
