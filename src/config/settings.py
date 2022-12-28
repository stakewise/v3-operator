from decouple import Choices, Csv, config
from web3 import Web3

from src.config.networks import GOERLI, NETWORKS, NetworkConfig

VAULT_CONTRACT_ADDRESS = Web3.to_checksum_address(config('VAULT_CONTRACT_ADDRESS'))

# connections
EXECUTION_ENDPOINT = config('EXECUTION_ENDPOINT')
CONSENSUS_ENDPOINT = config('CONSENSUS_ENDPOINT')

# postgres
POSTGRES_DB = config('POSTGRES_DB', default='operator')
POSTGRES_PORT = config('POSTGRES_PORT', default=5432, cast=int)
POSTGRES_USER = config('POSTGRES_USER', default='operator')
POSTGRES_HOSTNAME = config('POSTGRES_HOSTNAME')
POSTGRES_PASSWORD = config('POSTGRES_PASSWORD')

# keystores
KEYSTORES_PASSWORD = config('KEYSTORES_PASSWORD')
KEYSTORES_PATH = config('KEYSTORES_PATH')

# operator
OPERATOR_PRIVATE_KEY = config('OPERATOR_PRIVATE_KEY')

# ENS
# used to fetch oracles config from ENS when running on Gnosis
MAINNET_EXECUTION_ENDPOINT = config('MAINNET_EXECUTION_ENDPOINT', default='')
DAO_ENS_NAME = config('DAO_ENS_NAME', default='stakewise.eth')

# remote IPFS
IPFS_FETCH_ENDPOINTS = config(
    'IPFS_FETCH_ENDPOINTS',
    cast=Csv(),
    default='https://stakewise.infura-ipfs.io/,'
    'http://cloudflare-ipfs.com,'
    'https://gateway.pinata.cloud,https://ipfs.io',
)

# common
LOG_LEVEL = config('LOG_LEVEL', default='INFO')
DEPOSIT_AMOUNT = Web3.to_wei(32, 'ether')
DEPOSIT_AMOUNT_GWEI = int(Web3.from_wei(DEPOSIT_AMOUNT, 'gwei'))

# network
NETWORK = config('NETWORK', cast=Choices([GOERLI]))
NETWORK_CONFIG: NetworkConfig = NETWORKS[NETWORK]

APPROVAL_MAX_VALIDATORS = config('APPROVAL_MAX_VALIDATORS', default=10, cast=int)

# sentry config
SENTRY_DSN = config('SENTRY_DSN', default='')
