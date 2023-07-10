from functools import cached_property
from pathlib import Path

from decouple import Csv
from decouple import config as decouple_config
from web3 import Web3
from web3.types import ChecksumAddress

from src.config.networks import GOERLI, NETWORKS, NetworkConfig

DATA_DIR = Path.home() / '.stakewise'

DEFAULT_MAX_FEE_PER_GAS_GWEI = 70
DEFAULT_METRICS_HOST = '127.0.0.1'
DEFAULT_METRICS_PORT = 9100


class Singleton(type):
    _instances: dict = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# pylint: disable-next=too-many-public-methods
class Settings(metaclass=Singleton):
    vault: ChecksumAddress
    vault_dir: Path
    network: str
    consensus_endpoints: str
    execution_endpoints: str
    harvest_vault: bool | None
    verbose: bool
    metrics_host: str | None
    metrics_port: int | None
    deposit_data_file: str | None
    keystores_dir: str | None
    keystores_password_dir: str | None
    keystores_password_file: str | None
    hot_wallet_file: str | None
    hot_wallet_password_file: str | None
    max_fee_per_gas_gwei: int | None
    database_file: Path
    log_level: str
    ipfs_fetch_endpoints: list[str]
    validators_fetch_chunk_size: int
    sentry_dsn: str

    # pylint: disable-next=too-many-arguments,too-many-locals
    def set(
        self,
        vault: str,
        vault_dir: Path,
        network: str,
        consensus_endpoints: str = '',
        execution_endpoints: str = '',
        harvest_vault: bool | None = None,
        verbose: bool = False,
        deposit_data_file: str | None = None,
        keystores_dir: str | None = None,
        keystores_password_file: str | None = None,
        hot_wallet_file: str | None = None,
        hot_wallet_password_file: str | None = None,
        database_dir: str | None = None,
        metrics_port: int | None = None,
        metrics_host: str | None = None,
        max_fee_per_gas_gwei: int | None = None,
    ):
        self.vault = Web3.to_checksum_address(vault)
        self.vault_dir = vault_dir
        self.network = network

        self.consensus_endpoints = consensus_endpoints
        self.execution_endpoints = execution_endpoints
        self.harvest_vault = harvest_vault
        self.verbose = verbose
        self.metrics_host = metrics_host
        self.metrics_port = metrics_port
        self.max_fee_per_gas_gwei = max_fee_per_gas_gwei

        self.deposit_data_file = deposit_data_file
        # keystores
        self.keystores_dir = keystores_dir
        self.keystores_password_dir = decouple_config(
            'KEYSTORES_PASSWORD_DIR',
            default='',
        )
        self.keystores_password_file = keystores_password_file

        # hot wallet
        self.hot_wallet_file = hot_wallet_file
        self.hot_wallet_password_file = hot_wallet_password_file

        db_dir = Path(database_dir) if database_dir else vault_dir
        self.database_file = db_dir / 'operator.db'

        self.log_level = decouple_config('LOG_LEVEL', default='INFO')
        self.ipfs_fetch_endpoints = decouple_config(
            'IPFS_FETCH_ENDPOINTS',
            cast=Csv(),
            default='https://stakewise-v3.infura-ipfs.io,'
            'http://cloudflare-ipfs.com,'
            'https://gateway.pinata.cloud,https://ipfs.io',
        )
        self.validators_fetch_chunk_size = decouple_config(
            'VALIDATORS_FETCH_CHUNK_SIZE', default=100, cast=int
        )
        self.sentry_dsn = decouple_config('SENTRY_DSN', default='')

    @cached_property
    def VERBOSE(self) -> bool:
        return self.verbose

    @cached_property
    def LOG_LEVEL(self) -> str:
        return self.log_level

    @cached_property
    def NETWORK(self) -> str:
        return self.network

    @cached_property
    def NETWORK_CONFIG(self) -> NetworkConfig:
        return NETWORKS[self.NETWORK]

    @cached_property
    def EXECUTION_ENDPOINTS(self) -> list[str]:
        return [node.strip() for node in self.execution_endpoints.split(',')]

    @cached_property
    def CONSENSUS_ENDPOINTS(self) -> list[str]:
        return [node.strip() for node in self.consensus_endpoints.split(',')]

    @cached_property
    def IPFS_FETCH_ENDPOINTS(self) -> list[str]:
        return self.ipfs_fetch_endpoints

    @cached_property
    def VAULT(self) -> ChecksumAddress:
        return self.vault

    @cached_property
    def DATABASE(self) -> Path:
        return self.database_file

    @cached_property
    def KEYSTORES_DIR(self) -> Path:
        return Path(self.keystores_dir) if self.keystores_dir else self.vault_dir / 'keystores'

    @cached_property
    def KEYSTORES_PASSWORD_FILE(self) -> Path:
        return (
            Path(self.keystores_password_file)
            if self.keystores_password_file
            else self.vault_dir / 'keystores' / 'password.txt'
        )

    @cached_property
    def KEYSTORES_PASSWORD_DIR(self) -> Path:
        return (
            Path(self.keystores_password_dir)
            if self.keystores_password_dir
            else self.vault_dir / 'keystores'
        )

    @cached_property
    def DEPOSIT_DATA_FILE(self) -> Path:
        return (
            Path(self.deposit_data_file)
            if self.deposit_data_file
            else self.vault_dir / 'deposit_data.json'
        )

    @cached_property
    def HOT_WALLET_FILE(self) -> Path:
        return (
            Path(self.hot_wallet_file)
            if self.hot_wallet_file
            else self.vault_dir / 'wallet' / 'wallet.json'
        )

    @cached_property
    def HOT_WALLET_PASSWORD_FILE(self) -> Path:
        return (
            Path(self.hot_wallet_password_file)
            if self.hot_wallet_password_file
            else self.vault_dir / 'wallet' / 'password.txt'
        )

    @cached_property
    def HARVEST_VAULT(self) -> bool | None:
        return self.harvest_vault

    @cached_property
    def MAX_FEE_PER_GAS_GWEI(self) -> int:
        return self.max_fee_per_gas_gwei or DEFAULT_MAX_FEE_PER_GAS_GWEI

    @cached_property
    def VALIDATORS_FETCH_CHUNK_SIZE(self) -> int:
        return self.validators_fetch_chunk_size

    @cached_property
    def SENTRY_DSN(self) -> str:
        return self.sentry_dsn

    @cached_property
    def METRICS_HOST(self) -> str:
        return self.metrics_host or DEFAULT_METRICS_HOST

    @cached_property
    def METRICS_PORT(self) -> int:
        return self.metrics_port or DEFAULT_METRICS_PORT


settings = Settings()

AVAILABLE_NETWORKS = [GOERLI]

# oracles
UPDATE_SIGNATURES_URL_PATH = '/signatures'
OUTDATED_SIGNATURES_URL_PATH = '/signatures/{vault}'

# common
DEPOSIT_AMOUNT = Web3.to_wei(32, 'ether')
DEPOSIT_AMOUNT_GWEI = int(Web3.from_wei(DEPOSIT_AMOUNT, 'gwei'))

# Backoff retries
DEFAULT_RETRY_TIME = 60
