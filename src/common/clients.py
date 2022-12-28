import psycopg
from ens import AsyncENS
from sw_utils import IpfsFetchClient, get_consensus_client, get_execution_client
from web3 import Web3

from src.common.accounts import operator_account
from src.config.networks import GNOSIS
from src.config.settings import (
    CONSENSUS_ENDPOINT,
    EXECUTION_ENDPOINT,
    IPFS_FETCH_ENDPOINTS,
    MAINNET_EXECUTION_ENDPOINT,
    NETWORK,
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


def build_ens_client() -> AsyncENS:
    if NETWORK == GNOSIS:
        # use mainnet ENS for Gnosis as it's not deployed there
        return AsyncENS.from_web3(get_execution_client(MAINNET_EXECUTION_ENDPOINT))

    return AsyncENS.from_web3(execution_client)


def build_execution_client() -> Web3:
    w3 = get_execution_client(EXECUTION_ENDPOINT)
    w3.eth.default_account = operator_account.address
    return w3


execution_client = build_execution_client()
consensus_client = get_consensus_client(CONSENSUS_ENDPOINT)
db_client = Database()
ens_client = build_ens_client()
ipfs_fetch_client = IpfsFetchClient(IPFS_FETCH_ENDPOINTS)
