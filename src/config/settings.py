import os
from dataclasses import dataclass
from pathlib import Path

from decouple import Choices, Csv
from decouple import config as decouple_config
from web3 import Web3
from web3.types import ChecksumAddress

from src.config.networks import GOERLI, NETWORKS, NetworkConfig

CONFIG_DIR = Path.home() / '.stakewise'


class Singleton(type):
    _instances: dict = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


@dataclass(frozen=True)
# pylint: disable-next=too-many-public-methods
class SettingsStore(metaclass=Singleton):
    verbose: bool | None = None
    log_level: str | None = None
    network: str | None = None
    execution_endpoint: str | None = None
    consensus_endpoint: str | None = None
    ipfs_fetch_endpoints: list[str] | None = None
    vault: str | None = None
    database_dir: str | None = None
    keystores_path: Path | None = None
    keystores_password_file: Path | None = None
    keystores_password_dir: Path | None = None
    deposit_data_path: Path | None = None
    hot_wallet_private_key: str | None = None
    hot_wallet_keystore_path: Path | None = None
    hot_wallet_keystore_password_path: Path | None = None
    harvest_vault: bool | None = None
    max_fee_per_gas_gwei: int | None = None
    approval_max_validators: int | None = None
    validators_fetch_chunk_size: int | None = None
    sentry_dsn: str | None = None

    @property
    def VERBOSE(self) -> bool:
        return self.verbose or decouple_config('VERBOSE', default=False)

    @property
    def LOG_LEVEL(self) -> str:
        return self.log_level or decouple_config('LOG_LEVEL', default='INFO')

    @property
    def NETWORK(self) -> str:
        return self.network or decouple_config('NETWORK', cast=Choices([GOERLI]))

    @property
    def NETWORK_CONFIG(self) -> NetworkConfig:
        return NETWORKS[self.NETWORK]

    @property
    def EXECUTION_ENDPOINT(self) -> str:
        return self.execution_endpoint or decouple_config('EXECUTION_ENDPOINT')

    @property
    def CONSENSUS_ENDPOINT(self) -> str:
        return self.consensus_endpoint or decouple_config('CONSENSUS_ENDPOINT')

    @property
    def IPFS_FETCH_ENDPOINTS(self) -> list[str]:
        return self.ipfs_fetch_endpoints or decouple_config(
            'IPFS_FETCH_ENDPOINTS',
            cast=Csv(),
            default='https://stakewise-v3.infura-ipfs.io,'
            'http://cloudflare-ipfs.com,'
            'https://gateway.pinata.cloud,https://ipfs.io',
        )

    @property
    def VAULT_CONTRACT_ADDRESS(self) -> ChecksumAddress:
        if self.vault:
            return Web3.to_checksum_address(self.vault)
        return Web3.to_checksum_address(decouple_config('VAULT_CONTRACT_ADDRESS'))

    @property
    def VAULT_DIR(self) -> Path:
        return Path(CONFIG_DIR) / str(self.VAULT_CONTRACT_ADDRESS)

    @property
    def DATABASE(self) -> str:
        if self.database_dir:
            return os.path.join(self.database_dir, 'operator.db')
        return os.path.join(self.VAULT_DIR, 'operator.db')

    @property
    def KEYSTORES_PATH(self) -> Path:
        if self.keystores_path:
            return self.keystores_path
        return self.VAULT_DIR / 'keystores'

    @property
    def KEYSTORES_PASSWORD_FILE(self) -> Path | None:
        if self.keystores_password_file:
            return self.keystores_password_file
        if not self.KEYSTORES_PASSWORD_DIR:
            return self.VAULT_DIR / 'keystores' / 'password.txt'
        return None

    @property
    def KEYSTORES_PASSWORD_DIR(self) -> Path | None:
        return self.keystores_password_dir

    @property
    def DEPOSIT_DATA_PATH(self) -> Path:
        return self.deposit_data_path or self.VAULT_DIR / 'deposit_data.json'

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
            return self.VAULT_DIR / 'wallet' / 'wallet.json'
        return None

    @property
    def HOT_WALLET_KEYSTORE_PASSWORD_PATH(self) -> Path | None:
        if self.hot_wallet_keystore_password_path:
            return self.hot_wallet_keystore_password_path

        if not self.HOT_WALLET_PRIVATE_KEY:
            return self.VAULT_DIR / 'wallet' / 'password.txt'
        return None

    @property
    def HARVEST_VAULT(self) -> bool:
        return self.harvest_vault or decouple_config('HARVEST_VAULT', default=False, cast=bool)

    @property
    def MAX_FEE_PER_GAS_GWEI(self) -> int:
        return (
                self.max_fee_per_gas_gwei
                or
                decouple_config('MAX_FEE_PER_GAS_GWEI', default=70, cast=int)
        )

    @property
    def APPROVAL_MAX_VALIDATORS(self) -> int:
        return self.approval_max_validators or decouple_config(
         'APPROVAL_MAX_VALIDATORS', default=10, cast=int)

    @property
    def VALIDATORS_FETCH_CHUNK_SIZE(self) -> int:
        return self.validators_fetch_chunk_size or decouple_config(
            'VALIDATORS_FETCH_CHUNK_SIZE', default=100, cast=int
        )

    @property
    def SENTRY_DSN(self) -> str | None:
        return self.sentry_dsn

    @property
    def NETWORK_VALIDATORS_TABLE(self) -> str:
        return f'{self.NETWORK}_network_validators'


AVAILABLE_NETWORKS = [GOERLI]

# oracles
UPDATE_SIGNATURES_URL_PATH = '/signatures'
OUTDATED_SIGNATURES_URL_PATH = '/signatures/{vault}'

# common
DEPOSIT_AMOUNT = Web3.to_wei(32, 'ether')
DEPOSIT_AMOUNT_GWEI = int(Web3.from_wei(DEPOSIT_AMOUNT, 'gwei'))

# Backoff retries
DEFAULT_RETRY_TIME = 60
