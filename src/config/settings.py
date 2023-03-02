import os
import sys

from decouple import Choices, Csv, config
from web3 import Web3

from src.config.networks import GOERLI, NETWORKS, NetworkConfig

# debug
VERBOSE = '-v' in sys.argv

# network
NETWORK = config('NETWORK', cast=Choices([GOERLI]))
NETWORK_CONFIG: NetworkConfig = NETWORKS[NETWORK]

VAULT_CONTRACT_ADDRESS = Web3.to_checksum_address(config('VAULT_CONTRACT_ADDRESS'))

# connections
EXECUTION_ENDPOINT = config('EXECUTION_ENDPOINT')
CONSENSUS_ENDPOINT = config('CONSENSUS_ENDPOINT')

# database
DATABASE = os.path.join(config('DATABASE_DIR'), 'operator.db')

# keystores
KEYSTORES_PASSWORD_PATH = config('KEYSTORES_PASSWORD_PATH')
KEYSTORES_PATH = config('KEYSTORES_PATH')

# deposit data
DEPOSIT_DATA_PATH = config('DEPOSIT_DATA_PATH')

# operator private key
OPERATOR_PRIVATE_KEY = config('OPERATOR_PRIVATE_KEY', default=None)
OPERATOR_KEYSTORE_PATH = config('OPERATOR_KEYSTORE_PATH', default=None)
OPERATOR_KEYSTORE_PASSWORD_PATH = config('OPERATOR_KEYSTORE_PASSWORD_PATH', default=None)

# remote IPFS
IPFS_FETCH_ENDPOINTS = config(
    'IPFS_FETCH_ENDPOINTS',
    cast=Csv(),
    default='https://stakewise-v3.infura-ipfs.io,'
    'http://cloudflare-ipfs.com,'
    'https://gateway.pinata.cloud,https://ipfs.io',
)
GOERLI_GENESIS_VALIDATORS_IPFS_HASH = 'bafybeiaaje4dyompaq2eztxt47damfxub37dvftnzvdcdxxk4kpb32bntu'

# common
LOG_LEVEL = config('LOG_LEVEL', default='INFO')
DEPOSIT_AMOUNT = Web3.to_wei(32, 'ether')
DEPOSIT_AMOUNT_GWEI = int(Web3.from_wei(DEPOSIT_AMOUNT, 'gwei'))

APPROVAL_MAX_VALIDATORS = config('APPROVAL_MAX_VALIDATORS', default=10, cast=int)

# Backoff retries
DEFAULT_RETRY_TIME = 60

# sentry config
SENTRY_DSN = config('SENTRY_DSN', default='')
