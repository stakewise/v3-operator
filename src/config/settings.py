import os
from pathlib import Path

from decouple import Choices, Csv
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
    verbose: bool
    log_level: str
    network: str
    data_dir: Path
    vault_dir: Path
    execution_endpoint: str
    consensus_endpoint: str
    ipfs_fetch_endpoints: list[str]
    vault: str
    database_dir: str
    keystores_path: Path
    keystores_password_file: Path
    keystores_password_dir: Path
    deposit_data_path: Path
    hot_wallet_private_key: str
    hot_wallet_keystore_path: Path
    hot_wallet_keystore_password_path: Path
    harvest_vault: bool
    max_fee_per_gas_gwei: int
    approval_max_validators: int
    validators_fetch_chunk_size: int
    sentry_dsn: str
    metrics_host: str
    metrics_port: int

    # pylint: disable-next=too-many-arguments,too-many-locals
    def set(
        self,
        vault: str,
        network: str | None = None,
        data_dir: Path | None = None,
        verbose: bool | None = None,
        log_level: str | None = None,
        execution_endpoint: str | None = None,
        consensus_endpoint: str | None = None,
        ipfs_fetch_endpoints: list[str] | None = None,
        database_dir: str | None = None,
        keystores_path: Path | None = None,
        keystores_password_file: Path | None = None,
        keystores_password_dir: Path | None = None,
        deposit_data_path: Path | None = None,
        hot_wallet_private_key: str | None = None,
        hot_wallet_keystore_path: Path | None = None,
        hot_wallet_keystore_password_path: Path | None = None,
        harvest_vault: bool | None = None,
        max_fee_per_gas_gwei: int | None = None,
        approval_max_validators: int | None = None,
        validators_fetch_chunk_size: int | None = None,
        sentry_dsn: str | None = None,
        metrics_host: str | None = None,
        metrics_port: int | None = None,
    ):
        self.vault = vault
        self.network = network or decouple_config('NETWORK', cast=Choices([GOERLI]))
        self.verbose = verbose or decouple_config('VERBOSE', default=False)
        self.log_level = log_level or decouple_config('LOG_LEVEL', default='INFO')
        self.execution_endpoint = execution_endpoint or decouple_config(
            'EXECUTION_ENDPOINT', default=''
        )
        self.consensus_endpoint = consensus_endpoint or decouple_config(
            'CONSENSUS_ENDPOINT', default=''
        )
        self.ipfs_fetch_endpoints = ipfs_fetch_endpoints or decouple_config(
            'IPFS_FETCH_ENDPOINTS',
            cast=Csv(),
            default='https://stakewise-v3.infura-ipfs.io,'
            'http://cloudflare-ipfs.com,'
            'https://gateway.pinata.cloud,https://ipfs.io',
        )
        data_dir = data_dir or DATA_DIR
        self.vault_dir = Path(data_dir) / str(self.vault).lower()
        self.database_dir = database_dir or decouple_config('DATABASE_DIR', default=None)
        self.keystores_path = keystores_path or decouple_config('KEYSTORES_PATH', default=None)
        self.keystores_password_file = keystores_password_file or decouple_config(
            'KEYSTORES_PASSWORD_FILE', default=None
        )
        self.keystores_password_dir = keystores_password_dir or decouple_config(
            'KEYSTORES_PASSWORD_DIR', default=None
        )
        self.deposit_data_path = deposit_data_path or decouple_config(
            'DEPOSIT_DATA_PATH', default=None
        )
        self.hot_wallet_private_key = hot_wallet_private_key or decouple_config(
            'HOT_WALLET_PRIVATE_KEY', default=None
        )
        self.hot_wallet_keystore_path = hot_wallet_keystore_path or decouple_config(
            'HOT_WALLET_KEYSTORE_PATH', default=None
        )
        self.hot_wallet_keystore_password_path = (
            hot_wallet_keystore_password_path
            or decouple_config('HOT_WALLET_KEYSTORE_PASSWORD_PATH', default=None)
        )
        self.harvest_vault = harvest_vault or decouple_config(
            'HARVEST_VAULT', default=False, cast=bool
        )
        self.max_fee_per_gas_gwei = max_fee_per_gas_gwei or decouple_config(
            'MAX_FEE_PER_GAS_GWEI', default=70, cast=int
        )
        self.approval_max_validators = approval_max_validators or decouple_config(
            'APPROVAL_MAX_VALIDATORS', default=10, cast=int
        )
        self.validators_fetch_chunk_size = validators_fetch_chunk_size or decouple_config(
            'VALIDATORS_FETCH_CHUNK_SIZE', default=100, cast=int
        )
        self.sentry_dsn = sentry_dsn or decouple_config('SENTRY_DSN', default='')
        self.metrics_host = metrics_host or decouple_config('METRICS_HOST', default='127.0.0.1')
        self.metrics_port = metrics_port or decouple_config('METRICS_PORT', default=9100)

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
    def EXECUTION_ENDPOINT(self) -> str:
        return self.execution_endpoint

    @property
    def CONSENSUS_ENDPOINT(self) -> str:
        return self.consensus_endpoint

    @property
    def IPFS_FETCH_ENDPOINTS(self) -> list[str]:
        return self.ipfs_fetch_endpoints

    @property
    def VAULT_CONTRACT_ADDRESS(self) -> ChecksumAddress:
        return Web3.to_checksum_address(self.vault)

    @property
    def DATABASE(self) -> str:
        if self.database_dir:
            return os.path.join(self.database_dir, 'operator.db')
        return os.path.join(self.vault_dir, 'operator.db')

    @property
    def KEYSTORES_PATH(self) -> Path:
        if self.keystores_path:
            return self.keystores_path
        return self.vault_dir / 'keystores'

    @property
    def KEYSTORES_PASSWORD_FILE(self) -> Path | None:
        if self.keystores_password_file:
            return self.keystores_password_file
        if not self.KEYSTORES_PASSWORD_DIR:
            return self.vault_dir / 'keystores' / 'password.txt'
        return None

    @property
    def KEYSTORES_PASSWORD_DIR(self) -> Path | None:
        return self.keystores_password_dir

    @property
    def DEPOSIT_DATA_PATH(self) -> Path:
        return self.deposit_data_path or self.vault_dir / 'deposit_data.json'

    @property
    def HOT_WALLET_PRIVATE_KEY(self) -> str | None:
        if self.hot_wallet_private_key:
            return self.hot_wallet_private_key
        return None

    @property
    def HOT_WALLET_KEYSTORE_PATH(self) -> Path | None:
        if self.hot_wallet_keystore_path:
            return self.hot_wallet_keystore_path

        if not self.HOT_WALLET_PRIVATE_KEY:
            return self.vault_dir / 'wallet' / 'wallet.json'
        return None

    @property
    def HOT_WALLET_KEYSTORE_PASSWORD_PATH(self) -> Path | None:
        if self.hot_wallet_keystore_password_path:
            return self.hot_wallet_keystore_password_path

        if not self.HOT_WALLET_PRIVATE_KEY:
            return self.vault_dir / 'wallet' / 'password.txt'
        return None

    @property
    def HARVEST_VAULT(self) -> bool:
        return self.harvest_vault

    @property
    def MAX_FEE_PER_GAS_GWEI(self) -> int:
        return self.max_fee_per_gas_gwei

    @property
    def APPROVAL_MAX_VALIDATORS(self) -> int:
        return self.approval_max_validators

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
