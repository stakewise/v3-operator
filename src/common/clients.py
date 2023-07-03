import logging
import sqlite3
from functools import cached_property
from pathlib import Path

from sw_utils import (
    ExtendedAsyncBeacon,
    IpfsException,
    IpfsFetchClient,
    construct_async_sign_and_send_raw_middleware,
    get_consensus_client,
    get_execution_client,
)
from sw_utils.tenacity_decorators import custom_before_log
from tenacity import retry, retry_if_exception_type, stop_after_delay, wait_exponential
from web3 import Web3

from src.common.wallet import hot_wallet
from src.config.settings import DEFAULT_RETRY_TIME, settings

logger = logging.getLogger(__name__)


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
        return get_consensus_client(settings.CONSENSUS_ENDPOINT)

    def __getattr__(self, item):
        return getattr(self.client, item)


def retry_ipfs_exception(delay: int = DEFAULT_RETRY_TIME):
    return retry(
        retry=retry_if_exception_type(IpfsException),
        wait=wait_exponential(multiplier=1, min=1, max=delay // 2),
        stop=stop_after_delay(delay),
        before=custom_before_log(logger, logging.INFO),
    )


class IpfsFetchRetryClient:
    @cached_property
    def client(self) -> IpfsFetchClient:
        return IpfsFetchClient(endpoints=settings.IPFS_FETCH_ENDPOINTS)

    @retry_ipfs_exception(delay=DEFAULT_RETRY_TIME)
    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        return await self.client.fetch_bytes(ipfs_hash)

    @retry_ipfs_exception(delay=DEFAULT_RETRY_TIME)
    async def fetch_json(self, ipfs_hash: str) -> dict | list:
        return await self.client.fetch_json(ipfs_hash)


db_client = Database()
execution_client = ExecutionClient()
consensus_client = ConsensusClient()
ipfs_fetch_client = IpfsFetchRetryClient()
