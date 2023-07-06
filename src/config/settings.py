from pathlib import Path

from decouple import Csv
from decouple import config as decouple_config
from web3 import Web3
from web3.types import ChecksumAddress

from src.config.networks import GOERLI, NETWORKS, NetworkConfig

DATA_DIR = Path.home() / '.stakewise'


class Singleton(type):
    _instances: dict = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# pylint: disable-next=too-many-public-methods
class Settings(metaclass=Singleton):
    vault: ChecksumAddress
    consensus_endpoints: list[str]
    execution_endpoints: list[str]
    harvest_vault: bool
    verbose: bool
    metrics_host: str
    metrics_port: int
    network: str
    deposit_data_file: Path
    keystores_dir: Path
    keystores_password_dir: Path
    keystores_password_file: Path
    hot_wallet_file: Path
    hot_wallet_password_file: Path
    max_fee_per_gas_gwei: int
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
        consensus_endpoints: str,
        execution_endpoints: str,
        harvest_vault: bool,
        verbose: bool,
        metrics_host: str,
        metrics_port: int,
        max_fee_per_gas_gwei: int,
        network: str,
        deposit_data_file: str | None,
        keystores_dir: str | None,
        keystores_password_file: str | None,
        hot_wallet_file: str | None,
        hot_wallet_password_file: str | None,
        database_dir: str | None,
    ):
        self.vault = Web3.to_checksum_address(vault)
        self.consensus_endpoints = [node.strip() for node in consensus_endpoints.split(',')]
        self.execution_endpoints = [node.strip() for node in execution_endpoints.split(',')]
        self.harvest_vault = harvest_vault
        self.verbose = verbose
        self.metrics_host = metrics_host
        self.metrics_port = metrics_port
        self.max_fee_per_gas_gwei = max_fee_per_gas_gwei

        self.network = network
        self.deposit_data_file = (
            Path(deposit_data_file) if deposit_data_file else vault_dir / 'deposit_data.json'
        )
        # keystores
        self.keystores_dir = Path(keystores_dir) if keystores_dir else vault_dir / 'keystores'
        self.keystores_password_dir = decouple_config(
            'KEYSTORES_PASSWORD_DIR',
            cast=Path,
            default=vault_dir / 'keystores',
        )
        self.keystores_password_file = (
            Path(keystores_password_file)
            if keystores_password_file
            else vault_dir / 'keystores' / 'password.txt'
        )

        # hot wallet
        self.hot_wallet_file = (
            Path(hot_wallet_file) if hot_wallet_file else vault_dir / 'wallet' / 'wallet.json'
        )
        self.hot_wallet_password_file = (
            Path(hot_wallet_password_file)
            if hot_wallet_password_file
            else vault_dir / 'wallet' / 'password.txt'
        )
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

    @property
    def VERBOSE(self) -> bool:
        return self.verbose

    @property
    def LOG_LEVEL(self) -> str:
        return self.log_level

    @property
    def NETWORK(self) -> str:
        return self.network

    @property
    def NETWORK_CONFIG(self) -> NetworkConfig:
        return NETWORKS[self.NETWORK]

    @property
    def EXECUTION_ENDPOINTS(self) -> list[str]:
        return self.execution_endpoints

    @property
    def CONSENSUS_ENDPOINTS(self) -> list[str]:
        return self.consensus_endpoints

    @property
    def IPFS_FETCH_ENDPOINTS(self) -> list[str]:
        return self.ipfs_fetch_endpoints

    @property
    def VAULT(self) -> ChecksumAddress:
        return self.vault

    @property
    def DATABASE(self) -> Path:
        return self.database_file

    @property
    def KEYSTORES_DIR(self) -> Path:
        return self.keystores_dir

    @property
    def KEYSTORES_PASSWORD_FILE(self) -> Path:
        return self.keystores_password_file

    @property
    def KEYSTORES_PASSWORD_DIR(self) -> Path:
        return self.keystores_password_dir

    @property
    def DEPOSIT_DATA_FILE(self) -> Path:
        return self.deposit_data_file

    @property
    def HOT_WALLET_FILE(self) -> Path:
        return self.hot_wallet_file

    @property
    def HOT_WALLET_PASSWORD_FILE(self) -> Path:
        return self.hot_wallet_password_file

    @property
    def HARVEST_VAULT(self) -> bool:
        return self.harvest_vault

    @property
    def MAX_FEE_PER_GAS_GWEI(self) -> int:
        return self.max_fee_per_gas_gwei

    @property
    def VALIDATORS_FETCH_CHUNK_SIZE(self) -> int:
        return self.validators_fetch_chunk_size

    @property
    def SENTRY_DSN(self) -> str | None:
        return self.sentry_dsn

    @property
    def METRICS_HOST(self) -> str:
        return self.metrics_host

    @property
    def METRICS_PORT(self) -> int:
        return self.metrics_port


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
