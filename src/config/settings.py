import argparse
import os
import sys

from decouple import Choices, Csv, config
from web3 import Web3

from src.config.networks import GOERLI, NETWORKS, NetworkConfig
from src.utils import set_env

parser = argparse.ArgumentParser()
parser.add_argument('--network', type=str,
                    help='The network of the Vault. Choices are: mainnet, gnosis, goerli')
parser.add_argument('--vault-contract-address', type=str,
                    help='Address of the Vault to register validators for')
parser.add_argument('--database-dir', type=str,
                    help='The directory where the database will be created or read from')
parser.add_argument('--execution-endpoint', type=str,
                    help='API endpoint for the execution node')
parser.add_argument('--consensus-endpoint', type=str,
                    help='API endpoint for the consensus node')
parser.add_argument('--keystores-password-path', type=str,
                    help='Absolute path to the password file for decrypting keystores')
parser.add_argument('--keystores-path', type=str,
                    help='Absolute path to the directory with all the encrypted keystores')
parser.add_argument('--deposit-data-path', type=str,
                    help='Path to the deposit_data.json file')
parser.add_argument('--operator-private-key', type=str,
                    help='Private key of the hot wallet with ETH for submitting transactions')
parser.add_argument('--operator-keystore-path', type=str,
                    help='Absolute path to the directory with all the encrypted keystores')
parser.add_argument('--operator-keystore-password-path', type=str,
                    help='Absolute path to the password file for decrypting keystores')
args = parser.parse_args()


# debug
VERBOSE = '-v' in sys.argv

# network
set_env('NETWORK', args.network)
NETWORK = config('NETWORK', cast=Choices([GOERLI]))
NETWORK_CONFIG: NetworkConfig = NETWORKS[NETWORK]

set_env('VAULT_CONTRACT_ADDRESS', args.vault_contract_address)
VAULT_CONTRACT_ADDRESS = Web3.to_checksum_address(
    config('VAULT_CONTRACT_ADDRESS'))

# connections
set_env('EXECUTION_ENDPOINT', args.execution_endpoint)
EXECUTION_ENDPOINT = config('EXECUTION_ENDPOINT')
set_env('CONSENSUS_ENDPOINT', args.consensus_endpoint)
CONSENSUS_ENDPOINT = config('CONSENSUS_ENDPOINT')

# database
DATABASE = os.path.join(config('DATABASE_DIR'), 'operator.db')

# keystores
set_env('KEYSTORES_PASSWORD_PATH', args.keystores_password_path)
KEYSTORES_PASSWORD_PATH = config('KEYSTORES_PASSWORD_PATH')
set_env('KEYSTORES_PATH', args.keystores_path)
KEYSTORES_PATH = config('KEYSTORES_PATH')

# deposit data
set_env('DEPOSIT_DATA_PATH', args.deposit_data_path)
DEPOSIT_DATA_PATH = config('DEPOSIT_DATA_PATH')

# operator private key
set_env('KEYSTORES_PATH', args.keystores_path)
OPERATOR_PRIVATE_KEY = config('OPERATOR_PRIVATE_KEY', default=None)
set_env('OPERATOR_KEYSTORE_PATH', args.operator_keystore_path)
OPERATOR_KEYSTORE_PATH = config('OPERATOR_KEYSTORE_PATH', default=None)
set_env('OPERATOR_KEYSTORE_PASSWORD_PATH',
        args.operator_keystore_password_path)
OPERATOR_KEYSTORE_PASSWORD_PATH = config(
    'OPERATOR_KEYSTORE_PASSWORD_PATH', default=None)

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

APPROVAL_MAX_VALIDATORS = config(
    'APPROVAL_MAX_VALIDATORS', default=10, cast=int)

# Backoff retries
DEFAULT_RETRY_TIME = 60

# sentry config
SENTRY_DSN = config('SENTRY_DSN', default='')

# validators
VALIDATORS_FETCH_CHUNK_SIZE = config(
    'VALIDATORS_FETCH_CHUNK_SIZE', default=100, cast=int)
