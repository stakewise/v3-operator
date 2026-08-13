from pathlib import Path

from decouple import Csv
from eth_typing import BlockNumber
from web3 import Web3
from web3.types import ChecksumAddress, Gwei, Wei

from src.common.typings import Singleton, ValidatorType
from src.config.env_vars import decouple_config
from src.config.networks import MAINNET, NETWORKS, NetworkConfig

DATA_DIR = Path.home() / '.stakewise'

DEFAULT_METRICS_HOST = '127.0.0.1'
DEFAULT_METRICS_PORT = 9100
DEFAULT_METRICS_PREFIX = 'sw_operator'

DEFAULT_HASHI_VAULT_PARALLELISM = 8
DEFAULT_HASHI_VAULT_ENGINE_NAME = 'secret'

DEFAULT_MIN_DEPOSIT_AMOUNT = Web3.to_wei(10, 'ether')
DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI = Gwei(int(Web3.from_wei(DEFAULT_MIN_DEPOSIT_AMOUNT, 'gwei')))

DEFAULT_VAULT_MIN_BALANCE = Web3.to_wei(0, 'ether')
DEFAULT_VAULT_MIN_BALANCE_GWEI = Gwei(int(Web3.from_wei(DEFAULT_VAULT_MIN_BALANCE, 'gwei')))

DEFAULT_MIN_DEPOSIT_DELAY = 3600  # 1 hour

DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI = Gwei(1000)
DEFAULT_MAX_WITHDRAWAL_REQUEST_FEE_GWEI = Gwei(1000)

DEFAULT_CONSENSUS_ENDPOINT = 'http://localhost:5052'
DEFAULT_EXECUTION_ENDPOINT = 'http://localhost:8545'


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
    graph_endpoint: str
    graph_request_timeout: int
    graph_retry_timeout: int
    graph_page_size: int

    harvest_vault: bool
    claim_fee_splitter: bool
    disable_withdrawals: bool
    disable_validators_registration: bool
    disable_validators_funding: bool
    verbose: bool
    enable_metrics: bool
    metrics_host: str
    metrics_port: int
    metrics_prefix: str
    validator_type: ValidatorType
    keystores_dir: Path
    keystores_password_dir: Path
    keystores_password_file: Path
    remote_signer_url: str | None
    remote_signer_public_keys_url: str | None
    dappnode: bool = False
    hashi_vault_key_paths: list[str] | None
    hashi_vault_key_prefixes: list[str] | None
    hashi_vault_url: str | None
    hashi_vault_engine_name: str
    hashi_vault_token: str | None
    hashi_vault_parallelism: int
    wallet_file: Path
    wallet_password_file: Path
    max_fee_per_gas_gwei: Gwei
    database: Path

    log_level: str
    log_format: str
    web3_log_level: str
    gql_log_level: str

    ipfs_fetch_endpoints: list[str]
    ipfs_timeout: int
    ipfs_retry_timeout: int

    ipfs_upload_client_timeout: int
    ipfs_local_client_endpoint: str
    ipfs_local_username: str | None
    ipfs_local_password: str | None
    ipfs_pinata_api_key: str | None
    ipfs_pinata_secret_key: str | None

    genesis_validators_ipfs_timeout: int
    genesis_validators_ipfs_retry_timeout: int
    validators_fetch_chunk_size: int
    sentry_dsn: str
    sentry_environment: str
    concurrency: int | None

    relayer_endpoint: str
    relayer_timeout: int
    skip_startup_checks: bool

    # meta_vault
    meta_vault_min_deposit_amount_gwei: Gwei

    # high priority fee
    priority_fee_num_blocks: int = decouple_config(
        'PRIORITY_FEE_NUM_BLOCKS',
        default=10,
        cast=int,
        group='Gas',
        description='Number of recent blocks sampled to estimate the priority fee.',
    )
    priority_fee_percentile: float = decouple_config(
        'PRIORITY_FEE_PERCENTILE',
        default=80.0,
        cast=float,
        group='Gas',
        description='Percentile of the sampled priority fees used for transactions.',
    )

    disable_available_validators_warnings: bool = decouple_config(
        'DISABLE_AVAILABLE_VALIDATORS_WARNINGS',
        default=False,
        cast=bool,
        group='Logging',
        description='Suppress warnings logged when the vault has no validator keys available.',
    )
    disable_full_withdrawals: bool = decouple_config(
        'DISABLE_FULL_WITHDRAWALS',
        default=False,
        cast=bool,
        group='Withdrawals',
        description='Never fully exit validators, only process partial withdrawals.',
    )
    wallet_private_key: str | None = decouple_config(
        'WALLET_PRIVATE_KEY',
        default=None,
        group='Wallet',
        description='Hot wallet private key, as an alternative to the encrypted wallet file.',
    )

    min_deposit_amount_gwei: Gwei
    vault_min_balance_gwei: Gwei
    max_validator_balance_gwei: Gwei
    min_deposit_delay: int
    max_withdrawal_request_fee_gwei: Gwei

    vault_first_block: BlockNumber
    nodes_dir: Path

    run_nodes: bool
    enable_file_logging: bool
    log_file_path: Path | None

    # pylint: disable-next=too-many-arguments,too-many-locals,too-many-statements
    def set(
        self,
        vault: ChecksumAddress,
        vault_dir: Path,
        network: str,
        consensus_endpoints: str = '',
        execution_endpoints: str = '',
        execution_jwt_secret: str | None = None,
        graph_endpoint: str | None = None,
        harvest_vault: bool = False,
        claim_fee_splitter: bool = False,
        disable_withdrawals: bool = False,
        disable_validators_registration: bool = False,
        disable_validators_funding: bool = False,
        verbose: bool = False,
        enable_metrics: bool = False,
        metrics_port: int = DEFAULT_METRICS_PORT,
        metrics_host: str = DEFAULT_METRICS_HOST,
        metrics_prefix: str = DEFAULT_METRICS_PREFIX,
        max_fee_per_gas_gwei: int | None = None,
        validator_type: ValidatorType = ValidatorType.V2,
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
        wallet_file: str | None = None,
        wallet_password_file: str | None = None,
        database_dir: str | None = None,
        log_level: str | None = None,
        log_format: str | None = None,
        concurrency: int | None = None,
        relayer_endpoint: str | None = None,
        min_deposit_amount_gwei: Gwei = DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
        vault_min_balance_gwei: Gwei = DEFAULT_VAULT_MIN_BALANCE_GWEI,
        max_validator_balance_gwei: Gwei | None = None,
        min_deposit_delay: int = DEFAULT_MIN_DEPOSIT_DELAY,
        max_withdrawal_request_fee_gwei: Gwei = DEFAULT_MAX_WITHDRAWAL_REQUEST_FEE_GWEI,
        vault_first_block: BlockNumber | None = None,
        meta_vault_min_deposit_amount_gwei: Gwei = DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI,
        nodes_dir: Path = Path(''),
        run_nodes: bool = False,
        enable_file_logging: bool = False,
        log_file_path: Path | None = None,
    ) -> None:
        self.vault = vault
        vault_dir.mkdir(parents=True, exist_ok=True)
        self.vault_dir = vault_dir
        self.network = network

        if consensus_endpoints:
            self.consensus_endpoints = [node.strip() for node in consensus_endpoints.split(',')]
        else:
            self.consensus_endpoints = [DEFAULT_CONSENSUS_ENDPOINT]

        if execution_endpoints:
            self.execution_endpoints = [node.strip() for node in execution_endpoints.split(',')]
        else:
            self.execution_endpoints = [DEFAULT_EXECUTION_ENDPOINT]

        self.execution_jwt_secret = execution_jwt_secret
        self.graph_endpoint = graph_endpoint or self.network_config.STAKEWISE_GRAPH_ENDPOINT
        self.harvest_vault = harvest_vault
        self.claim_fee_splitter = claim_fee_splitter
        self.disable_withdrawals = disable_withdrawals
        self.disable_validators_registration = disable_validators_registration
        self.disable_validators_funding = disable_validators_funding
        self.verbose = verbose
        self.enable_metrics = enable_metrics
        self.metrics_host = metrics_host
        self.metrics_port = metrics_port
        self.metrics_prefix = metrics_prefix
        self.validator_type = validator_type

        if max_fee_per_gas_gwei is None:
            max_fee_per_gas_gwei = self.network_config.MAX_FEE_PER_GAS_GWEI
        self.max_fee_per_gas_gwei = Gwei(max_fee_per_gas_gwei)

        if max_validator_balance_gwei is None:
            max_validator_balance_gwei = self.network_config.MAX_VALIDATOR_BALANCE_GWEI
        self.max_validator_balance_gwei = Gwei(max_validator_balance_gwei)

        self.min_deposit_amount_gwei = min_deposit_amount_gwei
        self.vault_min_balance_gwei = vault_min_balance_gwei
        self.min_deposit_delay = min_deposit_delay
        self.max_withdrawal_request_fee_gwei = max_withdrawal_request_fee_gwei

        # keystores
        self.keystores_dir = Path(keystores_dir) if keystores_dir else vault_dir / 'keystores'
        self.keystores_password_dir = decouple_config(
            'KEYSTORES_PASSWORD_DIR',
            cast=Path,
            default=vault_dir / 'keystores',
            group='Keystores',
            description='Directory holding the per-keystore password files.',
            default_repr='<vault-dir>/keystores',
        )
        self.keystores_password_file = (
            Path(keystores_password_file)
            if keystores_password_file
            else vault_dir / 'keystores' / 'password.txt'
        )

        # remote signer configuration
        self.remote_signer_url = remote_signer_url
        self.remote_signer_public_keys_url: str = decouple_config(
            'REMOTE_SIGNER_PUBLIC_KEYS_URL',
            default=None,
            group='Remote signer',
            description=(
                'URL used to list the public keys held by the remote signer, '
                'when it differs from the signer URL.'
            ),
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

        # wallet
        self.wallet_file = (
            Path(wallet_file) if wallet_file else vault_dir / 'wallet' / 'wallet.json'
        )
        self.wallet_password_file = (
            Path(wallet_password_file)
            if wallet_password_file
            else vault_dir / 'wallet' / 'password.txt'
        )

        db_dir = Path(database_dir) if database_dir else vault_dir
        self.database = db_dir / 'operator.db'

        self.log_level = log_level or 'INFO'
        self.log_format = log_format or LOG_PLAIN
        self.web3_log_level = decouple_config(
            'WEB3_LOG_LEVEL',
            default='INFO',
            group='Logging',
            description='Log level of the web3 library.',
        )
        self.gql_log_level = decouple_config(
            'GQL_LOG_LEVEL',
            default='WARNING',
            group='Logging',
            description='Log level of the gql (subgraph client) library.',
        )

        self.sentry_dsn = decouple_config(
            'SENTRY_DSN',
            default='',
            group='Monitoring',
            description='Sentry DSN. Error reporting is disabled when empty.',
        )
        self.sentry_environment = decouple_config(
            'SENTRY_ENVIRONMENT',
            default='',
            group='Monitoring',
            description='Environment name reported to Sentry.',
        )

        self.ipfs_fetch_endpoints = decouple_config(
            'IPFS_FETCH_ENDPOINTS',
            cast=Csv(),
            default='https://ipfs.io,'
            'https://stakewise.myfilebase.com,'
            'https://stakewise-ipfs.quicknode-ipfs.com',
            group='IPFS',
            description='Comma separated IPFS gateways used to fetch oracle data.',
        )
        self.ipfs_timeout = decouple_config(
            'IPFS_TIMEOUT',
            default=60,
            cast=int,
            group='IPFS',
            description='Timeout of a single IPFS request, in seconds.',
        )
        self.ipfs_retry_timeout = decouple_config(
            'IPFS_RETRY_TIMEOUT',
            default=120,
            cast=int,
            group='IPFS',
            description='Total time spent retrying a failed IPFS request, in seconds.',
        )

        self.ipfs_upload_client_timeout = decouple_config(
            'IPFS_UPLOAD_CLIENT_TIMEOUT',
            default=30,
            cast=int,
            group='IPFS',
            description='Timeout of a single IPFS upload request, in seconds.',
        )

        # local IPFS
        self.ipfs_local_client_endpoint: str = decouple_config(
            'IPFS_LOCAL_CLIENT_ENDPOINT',
            default='',
            group='IPFS',
            description='Endpoint of a local/self-hosted IPFS node used to upload oracle data.',
        )
        self.ipfs_local_username: str | None = decouple_config(
            'IPFS_LOCAL_USERNAME',
            default=None,
            group='IPFS',
            description='Username for basic auth against the local IPFS node.',
        )
        self.ipfs_local_password: str | None = decouple_config(
            'IPFS_LOCAL_PASSWORD',
            default=None,
            group='IPFS',
            description='Password for basic auth against the local IPFS node.',
        )

        # pinata
        self.ipfs_pinata_api_key: str = decouple_config(
            'IPFS_PINATA_API_KEY',
            default='',
            group='IPFS',
            description=(
                'Pinata API key used to upload oracle data to the Pinata IPFS pinning service.'
            ),
        )
        self.ipfs_pinata_secret_key: str = decouple_config(
            'IPFS_PINATA_SECRET_KEY',
            default='',
            group='IPFS',
            description=(
                'Pinata secret key used to upload oracle data to the Pinata IPFS pinning service.'
            ),
        )

        # Genesis validators ipfs fetch may have larger timeouts
        self.genesis_validators_ipfs_timeout = decouple_config(
            'GENESIS_VALIDATORS_IPFS_TIMEOUT',
            default=300,
            cast=int,
            group='IPFS',
            description=(
                'Timeout of the genesis validators IPFS request, in seconds. '
                'Larger than IPFS_TIMEOUT because the file is big.'
            ),
        )
        self.genesis_validators_ipfs_retry_timeout = decouple_config(
            'GENESIS_VALIDATORS_IPFS_RETRY_TIMEOUT',
            default=600,
            cast=int,
            group='IPFS',
            description=(
                'Total time spent retrying the genesis validators IPFS request, in seconds.'
            ),
        )

        self.validators_fetch_chunk_size = decouple_config(
            'VALIDATORS_FETCH_CHUNK_SIZE',
            default=50000,
            cast=int,
            group='Consensus node',
            description='Number of validators requested from the beacon node in a single call.',
        )
        self.concurrency = concurrency
        self.execution_timeout = decouple_config(
            'EXECUTION_TIMEOUT',
            default=30,
            cast=int,
            group='Execution node',
            description='Timeout of a single execution node request, in seconds.',
        )
        self.execution_transaction_timeout = decouple_config(
            'EXECUTION_TRANSACTION_TIMEOUT',
            default=60,
            cast=int,
            group='Execution node',
            description='Time to wait for a submitted transaction receipt, in seconds.',
        )
        self.execution_retry_timeout = decouple_config(
            'EXECUTION_RETRY_TIMEOUT',
            default=60,
            cast=int,
            group='Execution node',
            description='Total time spent retrying a failed execution node request, in seconds.',
        )
        self.events_blocks_range_interval = decouple_config(
            'EVENTS_BLOCKS_RANGE_INTERVAL',
            default=43200 // self.network_config.SECONDS_PER_BLOCK,  # 12 hrs
            cast=int,
            group='Execution node',
            description=(
                'Block range size of a single eth_getLogs query. '
                'Lower it when the RPC provider rejects the range as too large.'
            ),
            default_repr='12 hours of blocks (3600 on mainnet, 8640 on gnosis)',
        )
        self.consensus_timeout = decouple_config(
            'CONSENSUS_TIMEOUT',
            default=60,
            cast=int,
            group='Consensus node',
            description='Timeout of a single consensus node request, in seconds.',
        )
        self.consensus_retry_timeout = decouple_config(
            'CONSENSUS_RETRY_TIMEOUT',
            default=120,
            cast=int,
            group='Consensus node',
            description='Total time spent retrying a failed consensus node request, in seconds.',
        )
        self.graph_request_timeout = decouple_config(
            'GRAPH_REQUEST_TIMEOUT',
            default=10,
            cast=int,
            group='Subgraph',
            description='Timeout of a single subgraph request, in seconds.',
        )
        self.graph_retry_timeout = decouple_config(
            'GRAPH_RETRY_TIMEOUT',
            default=60,
            cast=int,
            group='Subgraph',
            description='Total time spent retrying a failed subgraph request, in seconds.',
        )
        self.graph_page_size = decouple_config(
            'GRAPH_PAGE_SIZE',
            default=100,
            cast=int,
            group='Subgraph',
            description='Number of records requested from the subgraph per page.',
        )
        self.relayer_endpoint = relayer_endpoint or ''
        self.relayer_timeout = decouple_config(
            'RELAYER_TIMEOUT',
            default=10,
            cast=int,
            group='Relayer',
            description='Timeout of a single relayer request, in seconds.',
        )

        self.skip_startup_checks = decouple_config(
            'SKIP_STARTUP_CHECKS',
            default=False,
            cast=bool,
            group='Advanced',
            description=(
                'Skip the connectivity and configuration checks performed on startup. '
                'Intended for debugging.'
            ),
        )
        self.vault_first_block = vault_first_block or self.network_config.KEEPER_GENESIS_BLOCK
        self.meta_vault_min_deposit_amount_gwei = meta_vault_min_deposit_amount_gwei
        self.nodes_dir = nodes_dir
        self.run_nodes = run_nodes
        self.enable_file_logging = enable_file_logging
        self.log_file_path = log_file_path

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


settings = Settings()

DEFAULT_NETWORK = MAINNET

# oracles
UPDATE_SIGNATURES_URL_PATH = '/signatures'
OUTDATED_SIGNATURES_URL_PATH = '/signatures/{vault}'
ORACLES_VALIDATORS_TIMEOUT: int = decouple_config(
    'ORACLES_VALIDATORS_TIMEOUT',
    default=10,
    cast=int,
    group='Oracles',
    description='Timeout of a validator registration approval request, in seconds.',
)
ORACLES_CONSOLIDATION_TIMEOUT: int = decouple_config(
    'ORACLES_CONSOLIDATION_TIMEOUT',
    default=10,
    cast=int,
    group='Oracles',
    description='Timeout of a validator consolidation approval request, in seconds.',
)
ORACLES_EXITS_TIMEOUT: int = decouple_config(
    'ORACLES_EXITS_TIMEOUT',
    default=10,
    cast=int,
    group='Oracles',
    description='Timeout of an exit signature submission request, in seconds.',
)
# withdrawals
WITHDRAWALS_INTERVAL: int = decouple_config(
    'WITHDRAWALS_INTERVAL',
    default=43200,  # every 12 hr
    cast=int,
    group='Withdrawals',
    description='Minimum time between withdrawal processing runs, in seconds.',
)
MIN_WITHDRAWAL_AMOUNT_GWEI: Gwei = Gwei(1)

# common
MIN_ACTIVATION_BALANCE: Wei = Web3.to_wei(32, 'ether')
MIN_ACTIVATION_BALANCE_GWEI: Gwei = Gwei(int(Web3.from_wei(MIN_ACTIVATION_BALANCE, 'gwei')))

MIN_DEPOSIT_AMOUNT: Wei = Web3.to_wei(1, 'ether')
MIN_DEPOSIT_AMOUNT_GWEI: Gwei = Gwei(int(Web3.from_wei(MIN_DEPOSIT_AMOUNT, 'gwei')))

MAX_EFFECTIVE_BALANCE: Wei = Web3.to_wei(2048, 'ether')
MAX_EFFECTIVE_BALANCE_GWEI: Gwei = Gwei(int(Web3.from_wei(MAX_EFFECTIVE_BALANCE, 'gwei')))

EVENTS_CONCURRENCY_CHUNK: int = decouple_config(
    'EVENTS_CONCURRENCY_CHUNK',
    default=50_000,
    cast=int,
    group='Execution node',
    description='Block range size of a chunk when scanning contract logs concurrently.',
)
EVENTS_CONCURRENCY_LIMIT: int = decouple_config(
    'EVENTS_CONCURRENCY_LIMIT',
    default=10,
    cast=int,
    group='Execution node',
    description=(
        'Number of eth_getLogs queries sent in parallel when scanning contract logs. '
        'Lower it to reduce the load on rate limited RPC providers.'
    ),
)

# Maximum number of updateState calls batched into a single multicall transaction.
MULTICALL_CHUNK_SIZE: int = decouple_config(
    'MULTICALL_CHUNK_SIZE',
    default=20,
    cast=int,
    group='Redemptions',
    description='Maximum number of updateState calls batched into a single multicall transaction.',
)

# Backoff retries
DEFAULT_RETRY_TIME = 60

# Remote signer
REMOTE_SIGNER_UPLOAD_CHUNK_SIZE = decouple_config(
    'REMOTE_SIGNER_UPLOAD_CHUNK_SIZE',
    cast=int,
    default=5,
    group='Remote signer',
    description='Number of keystores uploaded to the remote signer in a single request.',
)
REMOTE_SIGNER_TIMEOUT = decouple_config(
    'REMOTE_SIGNER_TIMEOUT',
    cast=int,
    default=30,
    group='Remote signer',
    description='Timeout of a single remote signer request, in seconds.',
)

# Hashi vault timeout
HASHI_VAULT_TIMEOUT = 10

ATTEMPTS_WITH_DEFAULT_GAS: int = decouple_config(
    'ATTEMPTS_WITH_DEFAULT_GAS',
    default=3,
    cast=int,
    group='Gas',
    description=(
        'Number of transaction attempts made with the default gas price '
        'before the priority fee is raised.'
    ),
)

# Validators funding batch size
VALIDATORS_FUNDING_BATCH_SIZE = decouple_config(
    'VALIDATORS_FUNDING_BATCH_SIZE',
    cast=int,
    default=10,
    group='Validators',
    description='Number of validators funded in a single transaction.',
)

# Batch size for OsTokenRedeemer read-only multicalls (e.g. fetching processed shares in bulk)
OS_TOKEN_REDEEMER_CHUNK_SIZE: int = decouple_config(
    'OS_TOKEN_REDEEMER_CHUNK_SIZE',
    cast=int,
    default=1000,
    group='Redemptions',
    description=(
        'Batch size for OsTokenRedeemer read-only multicalls, '
        'e.g. fetching processed shares in bulk.'
    ),
)

# Minimum amount of rewards to process reward splitter
FEE_SPLITTER_MIN_ASSETS: int = decouple_config(
    'FEE_SPLITTER_MIN_ASSETS',
    default=Web3.to_wei('0.001', 'ether'),
    cast=int,
    group='Fee splitter',
    description='Minimum accrued rewards, in wei, before the fee splitter is claimed.',
)
FEE_SPLITTER_INTERVAL: int = decouple_config(
    'FEE_SPLITTER_INTERVAL',
    default=86400,  # every 24 hr
    cast=int,
    group='Fee splitter',
    description='Minimum time between fee splitter claims, in seconds.',
)

# logging
LOG_PLAIN = 'plain'
LOG_JSON = 'json'
LOG_FORMATS = [LOG_PLAIN, LOG_JSON]
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
LOG_WHITELISTED_DOMAINS = decouple_config(
    'LOG_WHITELISTED_DOMAINS',
    cast=Csv(),
    default='stakewise.io,localhost',
    group='Logging',
    description=(
        'Comma separated domains whose URLs are logged in full. '
        'URLs of other domains are hidden to avoid leaking API tokens.'
    ),
)
