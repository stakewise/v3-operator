from pathlib import Path

from decouple import Csv
from decouple import config as decouple_config
from web3 import Web3
from web3.types import ChecksumAddress

from src.config.networks import GOERLI, NETWORKS, NetworkConfig

DATA_DIR = Path.home() / '.stakewise'

DEFAULT_MAX_FEE_PER_GAS_GWEI = 100
DEFAULT_METRICS_HOST = '127.0.0.1'
DEFAULT_METRICS_PORT = 9100


class Singleton(type):
    _instances: dict = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


# pylint: disable-next=too-many-public-methods,too-many-instance-attributes
class Settings(metaclass=Singleton):
    vault: ChecksumAddress
    vault_dir: Path
    network: str
    consensus_endpoints: list[str]
    execution_endpoints: list[str]

    harvest_vault: bool
    verbose: bool
    metrics_host: str
    metrics_port: int
    deposit_data_file: Path
    keystores_dir: Path
    keystores_password_dir: Path
    keystores_password_file: Path
    remote_signer_config_file: Path
    remote_signer_url: str | None
    hot_wallet_file: Path
    hot_wallet_password_file: Path
    max_fee_per_gas_gwei: int
    database: Path
    log_level: str
    ipfs_fetch_endpoints: list[str]
    validators_fetch_chunk_size: int
    sentry_dsn: str
    pool_size: int | None

    # pylint: disable-next=too-many-arguments,too-many-locals
    def set(
        self,
        vault: str,
        vault_dir: Path,
        network: str,
        consensus_endpoints: str = '',
        execution_endpoints: str = '',
        harvest_vault: bool = False,
        verbose: bool = False,
        metrics_port: int = DEFAULT_METRICS_PORT,
        metrics_host: str = DEFAULT_METRICS_HOST,
        max_fee_per_gas_gwei: int = DEFAULT_MAX_FEE_PER_GAS_GWEI,
        deposit_data_file: str | None = None,
        keystores_dir: str | None = None,
        keystores_password_file: str | None = None,
        remote_signer_config_file: str | None = None,
        remote_signer_url: str | None = None,
        hot_wallet_file: str | None = None,
        hot_wallet_password_file: str | None = None,
        database_dir: str | None = None,
    ):
        self.vault = Web3.to_checksum_address(vault)
        vault_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir = vault_dir
        self.network = network

        self.consensus_endpoints = [node.strip() for node in consensus_endpoints.split(',')]
        self.execution_endpoints = [node.strip() for node in execution_endpoints.split(',')]
        self.harvest_vault = harvest_vault
        self.verbose = verbose
        self.metrics_host = metrics_host
        self.metrics_port = metrics_port
        self.max_fee_per_gas_gwei = max_fee_per_gas_gwei

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

        # remote signer configuration
        self.remote_signer_config_file = (
            Path(remote_signer_config_file)
            if remote_signer_config_file
            else vault_dir / 'remote_signer_config.json'
        )
        self.remote_signer_url = remote_signer_url

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
        self.database = db_dir / 'operator.db'

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
        self.pool_size = decouple_config(
            'POOL_SIZE', default=None, cast=lambda x: int(x) if x else None
        )

    @property
    def network_config(self) -> NetworkConfig:
        return NETWORKS[self.network]


settings = Settings()

AVAILABLE_NETWORKS = [GOERLI]

# oracles
UPDATE_SIGNATURES_URL_PATH = '/signatures'
OUTDATED_SIGNATURES_URL_PATH = '/signatures/{vault}'
ORACLES_VALIDATORS_TIMEOUT: int = decouple_config(
    'ORACLES_VALIDATORS_TIMEOUT', default=10, cast=int
)

# common
DEPOSIT_AMOUNT = Web3.to_wei(32, 'ether')
DEPOSIT_AMOUNT_GWEI = int(Web3.from_wei(DEPOSIT_AMOUNT, 'gwei'))

# Backoff retries
DEFAULT_RETRY_TIME = 60

# Remote signer timeout
REMOTE_SIGNER_TIMEOUT = 10
