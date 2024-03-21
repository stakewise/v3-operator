from pathlib import Path

from decouple import Csv
from decouple import config as decouple_config
from web3 import Web3
from web3.types import ChecksumAddress

from src.config.networks import HOLESKY, MAINNET, NETWORKS, NetworkConfig
from src.validators.typings import ValidatorsRegistrationMode

DATA_DIR = Path.home() / '.stakewise'

DEFAULT_MAX_FEE_PER_GAS_GWEI = 100

DEFAULT_METRICS_HOST = '127.0.0.1'
DEFAULT_METRICS_PORT = 9100

DEFAULT_API_HOST = '127.0.0.1'
DEFAULT_API_PORT = 8000


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
    consensus_timeout: int
    consensus_retry_timeout: int
    execution_endpoints: list[str]
    execution_timeout: int
    execution_transaction_timeout: int
    execution_retry_timeout: int

    harvest_vault: bool
    verbose: bool
    enable_metrics: bool
    metrics_host: str
    metrics_port: int
    deposit_data_file: Path
    keystores_dir: Path
    keystores_password_dir: Path
    keystores_password_file: Path
    remote_signer_url: str | None
    hashi_vault_key_path: str | None
    hashi_vault_url: str | None
    hashi_vault_token: str | None
    hot_wallet_file: Path
    hot_wallet_password_file: Path
    max_fee_per_gas_gwei: int
    database: Path

    log_level: str
    log_format: str
    web3_log_level: str

    ipfs_fetch_endpoints: list[str]
    ipfs_timeout: int
    ipfs_retry_timeout: int
    genesis_validators_ipfs_timeout: int
    genesis_validators_ipfs_retry_timeout: int
    validators_fetch_chunk_size: int
    sentry_dsn: str
    pool_size: int | None

    api_host: str
    api_port: int
    validators_registration_mode: ValidatorsRegistrationMode
    skip_startup_checks: bool

    # high priority fee
    priority_fee_num_blocks: int = decouple_config('PRIORITY_FEE_NUM_BLOCKS', default=10, cast=int)
    priority_fee_percentile: float = decouple_config(
        'PRIORITY_FEE_PERCENTILE', default=80.0, cast=float
    )

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
        enable_metrics: bool = False,
        metrics_port: int = DEFAULT_METRICS_PORT,
        metrics_host: str = DEFAULT_METRICS_HOST,
        max_fee_per_gas_gwei: int = DEFAULT_MAX_FEE_PER_GAS_GWEI,
        deposit_data_file: str | None = None,
        keystores_dir: str | None = None,
        keystores_password_file: str | None = None,
        remote_signer_url: str | None = None,
        hashi_vault_key_path: str | None = None,
        hashi_vault_url: str | None = None,
        hashi_vault_token: str | None = None,
        hot_wallet_file: str | None = None,
        hot_wallet_password_file: str | None = None,
        database_dir: str | None = None,
        log_level: str | None = None,
        log_format: str | None = None,
        pool_size: int | None = None,
        api_host: str = DEFAULT_API_HOST,
        api_port: int = DEFAULT_API_PORT,
        validators_registration_mode: ValidatorsRegistrationMode = ValidatorsRegistrationMode.AUTO,
    ) -> None:
        self.vault = Web3.to_checksum_address(vault)
        vault_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir = vault_dir
        self.network = network

        self.consensus_endpoints = [node.strip() for node in consensus_endpoints.split(',')]
        self.execution_endpoints = [node.strip() for node in execution_endpoints.split(',')]
        self.harvest_vault = harvest_vault
        self.verbose = verbose
        self.enable_metrics = enable_metrics
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
        self.remote_signer_url = remote_signer_url

        # hashi vault configuration
        self.hashi_vault_url = hashi_vault_url
        self.hashi_vault_key_path = hashi_vault_key_path
        self.hashi_vault_token = hashi_vault_token

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

        self.log_level = log_level or 'INFO'
        self.log_format = log_format or LOG_PLAIN
        self.web3_log_level = decouple_config('WEB3_LOG_LEVEL', default='INFO')

        self.sentry_dsn = decouple_config('SENTRY_DSN', default='')

        self.ipfs_fetch_endpoints = decouple_config(
            'IPFS_FETCH_ENDPOINTS',
            cast=Csv(),
            default='https://stakewise-v3.infura-ipfs.io,'
            'http://cloudflare-ipfs.com,'
            'https://gateway.pinata.cloud,https://ipfs.io',
        )
        self.ipfs_timeout = decouple_config('IPFS_TIMEOUT', default=60, cast=int)
        self.ipfs_retry_timeout = decouple_config('IPFS_RETRY_TIMEOUT', default=120, cast=int)

        # Genesis validators ipfs fetch may have larger timeouts
        self.genesis_validators_ipfs_timeout = decouple_config(
            'GENESIS_VALIDATORS_IPFS_TIMEOUT', default=300, cast=int
        )
        self.genesis_validators_ipfs_retry_timeout = decouple_config(
            'GENESIS_VALIDATORS_IPFS_RETRY_TIMEOUT', default=600, cast=int
        )

        self.validators_fetch_chunk_size = decouple_config(
            'VALIDATORS_FETCH_CHUNK_SIZE', default=100, cast=int
        )
        self.pool_size = pool_size
        self.execution_timeout = decouple_config('EXECUTION_TIMEOUT', default=30, cast=int)
        self.execution_transaction_timeout = decouple_config(
            'EXECUTION_TRANSACTION_TIMEOUT', default=300, cast=int
        )
        self.execution_retry_timeout = decouple_config(
            'EXECUTION_RETRY_TIMEOUT', default=60, cast=int
        )
        self.consensus_timeout = decouple_config('CONSENSUS_TIMEOUT', default=60, cast=int)
        self.consensus_retry_timeout = decouple_config(
            'CONSENSUS_RETRY_TIMEOUT', default=120, cast=int
        )
        self.api_host = api_host
        self.api_port = api_port
        self.validators_registration_mode = validators_registration_mode

        self.skip_startup_checks = decouple_config('SKIP_STARTUP_CHECKS', default=False, cast=bool)

    @property
    def keystore_cls_str(self) -> str:
        if self.remote_signer_url:
            return 'RemoteSignerKeystore'
        if self.hashi_vault_url:
            return 'HashiVaultKeystore'
        return 'LocalKeystore'

    @property
    def network_config(self) -> NetworkConfig:
        return NETWORKS[self.network]

    @property
    def is_genesis_vault(self) -> bool:
        return self.vault == settings.network_config.GENESIS_VAULT_CONTRACT_ADDRESS


settings = Settings()

AVAILABLE_NETWORKS = [MAINNET, HOLESKY]
DEFAULT_NETWORK = MAINNET

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

# Remote signer
REMOTE_SIGNER_UPLOAD_CHUNK_SIZE = decouple_config(
    'REMOTE_SIGNER_UPLOAD_CHUNK_SIZE', cast=int, default=5
)
REMOTE_SIGNER_TIMEOUT = decouple_config('REMOTE_SIGNER_TIMEOUT', cast=int, default=30)

# Hashi vault timeout
HASHI_VAULT_TIMEOUT = 10

# logging
LOG_PLAIN = 'plain'
LOG_JSON = 'json'
LOG_FORMATS = [LOG_PLAIN, LOG_JSON]
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
