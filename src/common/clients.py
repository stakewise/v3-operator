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
from sw_utils.graph.client import GraphClient as SWGraphClient
from web3 import AsyncWeb3
from web3.middleware import SignAndSendRawMiddlewareBuilder

import src
from src.common.wallet import wallet
from src.config.settings import settings

logger = logging.getLogger(__name__)

OPERATOR_USER_AGENT = f'StakeWise Operator {src.__version__}'


class Database:
    def get_db_connection(self) -> Connection:
        return sqlite3.connect(settings.database)

    def create_db_dir(self) -> None:
        settings.database.parent.mkdir(parents=True, exist_ok=True)


class ExecutionClient:
    client: AsyncWeb3
    is_set_up = False

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
            user_agent=OPERATOR_USER_AGENT,
        )
        # Account is required when emitting transactions.
        # For read-only queries account may be omitted.
        if wallet.can_load():
            w3.middleware_onion.inject(
                # pylint: disable-next=no-value-for-parameter
                SignAndSendRawMiddlewareBuilder.build(wallet.account),
                layer=0,
            )
            w3.eth.default_account = wallet.address

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
            user_agent=OPERATOR_USER_AGENT,
        )

    def __getattr__(self, item):  # type: ignore
        return getattr(self.client, item)


class GraphClient:
    @cached_property
    def client(self) -> SWGraphClient:
        return SWGraphClient(
            endpoint=settings.graph_endpoint,
            request_timeout=settings.graph_request_timeout,
            retry_timeout=settings.graph_retry_timeout,
            page_size=settings.graph_page_size,
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
graph_client = cast(SWGraphClient, GraphClient())
ipfs_fetch_client = IpfsLazyFetchClient()


async def setup_clients() -> None:
    await execution_client.setup()  # type: ignore
    await execution_non_retry_client.setup()  # type: ignore


async def close_clients() -> None:
    await execution_client.provider.disconnect()
    await execution_non_retry_client.provider.disconnect()
    await consensus_client.disconnect()
