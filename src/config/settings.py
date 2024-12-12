from pathlib import Path

from decouple import Csv
from decouple import config as decouple_config
from web3 import Web3
from web3.types import ChecksumAddress

from src.common.typings import Singleton
from src.config.networks import MAINNET, NETWORKS, NetworkConfig
from src.validators.typings import RelayerTypes, ValidatorsRegistrationMode

DATA_DIR = Path.home() / '.stakewise'

DEFAULT_MAX_FEE_PER_GAS_GWEI = 100

DEFAULT_METRICS_HOST = '127.0.0.1'
DEFAULT_METRICS_PORT = 9100
DEFAULT_METRICS_PREFIX = 'sw_operator'

DEFAULT_MIN_VALIDATORS_REGISTRATION = 1

DEFAULT_HASHI_VAULT_PARALLELISM = 8
DEFAULT_HASHI_VAULT_ENGINE_NAME = 'secret'


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
    events_blocks_range_interval: int
    execution_jwt_secret: str | None

    harvest_vault: bool
    verbose: bool
    enable_metrics: bool
    metrics_host: str
    metrics_port: int
    metrics_prefix: str
    deposit_data_file: Path
    keystores_dir: Path
    keystores_password_dir: Path
    keystores_password_file: Path
    remote_signer_url: str | None
    remote_signer_public_keys_url: str | None
    remote_signer_use_deposit_data: bool
    dappnode: bool = False
    hashi_vault_key_paths: list[str] | None
    hashi_vault_key_prefixes: list[str] | None
    hashi_vault_url: str | None
    hashi_vault_engine_name: str
    hashi_vault_token: str | None
    hashi_vault_parallelism: int
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
    sentry_environment: str
    pool_size: int | None

    relayer_type: str
    relayer_endpoint: str
    relayer_timeout: int
    validators_registration_mode: ValidatorsRegistrationMode
    skip_startup_checks: bool

    # high priority fee
    priority_fee_num_blocks: int = decouple_config('PRIORITY_FEE_NUM_BLOCKS', default=10, cast=int)
    priority_fee_percentile: float = decouple_config(
        'PRIORITY_FEE_PERCENTILE', default=80.0, cast=float
    )

    disable_deposit_data_warnings: bool = decouple_config(
        'DISABLE_DEPOSIT_DATA_WARNINGS', default=False, cast=bool
    )

    min_validators_registration: int

    # pylint: disable-next=too-many-arguments,too-many-locals,too-many-statements
    def set(
        self,
        vault: str,
        vault_dir: Path,
        network: str,
        consensus_endpoints: str = '',
        execution_endpoints: str = '',
        execution_jwt_secret: str | None = None,
        harvest_vault: bool = False,
        verbose: bool = False,
        enable_metrics: bool = False,
        metrics_port: int = DEFAULT_METRICS_PORT,
        metrics_host: str = DEFAULT_METRICS_HOST,
        metrics_prefix: str = DEFAULT_METRICS_PREFIX,
        max_fee_per_gas_gwei: int = DEFAULT_MAX_FEE_PER_GAS_GWEI,
        deposit_data_file: str | None = None,
        keystores_dir: str | None = None,
        keystores_password_file: str | None = None,
        remote_signer_url: str | None = None,
        dappnode: bool = False,
        hashi_vault_key_paths: list[str] | None = None,
        hashi_vault_key_prefixes: list[str] | None = None,
        hashi_vault_url: str | None = None,
        hashi_vault_engine_name: str = DEFAULT_HASHI_VAULT_ENGINE_NAME,
        hashi_vault_token: str | None = None,
        hashi_vault_parallelism: int = DEFAULT_HASHI_VAULT_PARALLELISM,
        hot_wallet_file: str | None = None,
        hot_wallet_password_file: str | None = None,
        database_dir: str | None = None,
        log_level: str | None = None,
        log_format: str | None = None,
        pool_size: int | None = None,
        relayer_type: str = RelayerTypes.DEFAULT,
        relayer_endpoint: str | None = None,
        validators_registration_mode: ValidatorsRegistrationMode = ValidatorsRegistrationMode.AUTO,
        min_validators_registration: int = DEFAULT_MIN_VALIDATORS_REGISTRATION,
    ) -> None:
        self.vault = Web3.to_checksum_address(vault)
        vault_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir = vault_dir
        self.network = network

        self.consensus_endpoints = [node.strip() for node in consensus_endpoints.split(',')]
        self.execution_endpoints = [node.strip() for node in execution_endpoints.split(',')]
        self.execution_jwt_secret = execution_jwt_secret
        self.harvest_vault = harvest_vault
        self.verbose = verbose
        self.enable_metrics = enable_metrics
        self.metrics_host = metrics_host
        self.metrics_port = metrics_port
        self.metrics_prefix = metrics_prefix
        self.max_fee_per_gas_gwei = max_fee_per_gas_gwei
        self.min_validators_registration = min_validators_registration

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
        self.remote_signer_public_keys_url: str = decouple_config(
            'REMOTE_SIGNER_PUBLIC_KEYS_URL', default=None
        )
        self.remote_signer_use_deposit_data: bool = decouple_config(
            'REMOTE_SIGNER_USE_DEPOSIT_DATA', default=False, cast=bool
        )
        self.dappnode = dappnode

        # hashi vault configuration
        if hashi_vault_key_paths is not None:
            if len(set(hashi_vault_key_paths)) != len(hashi_vault_key_paths):
                raise RuntimeError('Found duplicate addresses in hashi vault key paths')

        self.hashi_vault_url = hashi_vault_url
        self.hashi_vault_engine_name = hashi_vault_engine_name
        self.hashi_vault_key_paths = hashi_vault_key_paths
        self.hashi_vault_key_prefixes = hashi_vault_key_prefixes
        self.hashi_vault_token = hashi_vault_token
        self.hashi_vault_parallelism = hashi_vault_parallelism

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
        self.sentry_environment = decouple_config('SENTRY_ENVIRONMENT', default='')

        self.ipfs_fetch_endpoints = decouple_config(
            'IPFS_FETCH_ENDPOINTS',
            cast=Csv(),
            default='https://stakewise-v3.infura-ipfs.io,'
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
        self.events_blocks_range_interval = decouple_config(
            'EVENTS_BLOCKS_RANGE_INTERVAL',
            default=43200 // self.network_config.SECONDS_PER_BLOCK,  # 12 hrs
            cast=int,
        )
        self.consensus_timeout = decouple_config('CONSENSUS_TIMEOUT', default=60, cast=int)
        self.consensus_retry_timeout = decouple_config(
            'CONSENSUS_RETRY_TIMEOUT', default=120, cast=int
        )
        self.relayer_type = relayer_type
        self.relayer_endpoint = relayer_endpoint or ''
        self.relayer_timeout = decouple_config('RELAYER_TIMEOUT', default=10, cast=int)

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

    @property
    def need_deposit_data_file(self) -> bool:
        if self.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
            return True

        # At this point validators_registration_mode is API
        if self.relayer_type == RelayerTypes.DVT:
            # Validator registration data is taken from deposit data file.
            # DVT Relayer provides exit signature.
            return True

        # Validator registration data is provided by Relayer.
        # Validators manager signature is used instead of Merkle proof.
        return False


settings = Settings()

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

# Graphql timeout
GRAPH_API_TIMEOUT = 10

# logging
LOG_PLAIN = 'plain'
LOG_JSON = 'json'
LOG_FORMATS = [LOG_PLAIN, LOG_JSON]
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
