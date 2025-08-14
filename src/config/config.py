import json
import re
import shutil
from pathlib import Path

from src.common.credentials import CredentialManager
from src.config.networks import AVAILABLE_NETWORKS


class OperatorConfigException(ValueError):
    can_be_migrated = False

    def __init__(self, message: str, can_be_migrated: bool = False):
        super().__init__(message)
        self.can_be_migrated = can_be_migrated


class OperatorConfig:
    network: str = ''
    mnemonic_next_index: int = 0
    first_public_key: str | None = None

    def __init__(
        self,
        data_dir: Path,
    ):
        self.root_dir = Path(data_dir)

    @property
    def data_dir(self) -> Path:
        return self.root_dir / self.network

    @property
    def config_path(self) -> Path:
        return self.data_dir / 'config.json'

    @property
    def tmp_data_dir(self) -> Path:
        return self.data_dir / '.tmp'

    @property
    def keystores_dir(self) -> Path:
        return self.data_dir / 'keystores'

    @property
    def keystores_password_file(self) -> Path:
        return self.keystores_dir / 'password.txt'

    def create_tmp_dir(self) -> None:
        self.tmp_data_dir.mkdir(parents=True, exist_ok=True)

    def remove_tmp_dir(self) -> None:
        shutil.rmtree(self.tmp_data_dir)

    def load(self, network: str | None = None, mnemonic: str | None = None) -> None:
        if network:
            self.network = network
        else:
            # trying to guess network from root_dir
            dirs = [f for f in self.root_dir.iterdir() if f.is_dir()]
            # if there is only one network directory, use it
            network_directory_names = [d.name for d in dirs if d.name in AVAILABLE_NETWORKS]
            if len(dirs) and len(network_directory_names) == 1:
                self.network = network_directory_names[0]
            # if there is vault directory from single setup, trying to migrate to multivault
            elif len(dirs) and any(d.name.startswith('0x') for d in dirs):
                raise OperatorConfigException(
                    'Specify the `network` parameter', can_be_migrated=True
                )
            else:
                raise OperatorConfigException('Specify the `network` parameter')

        if self.config_path.is_file():
            with self.config_path.open('r') as f:
                config = json.load(f)
            self.network = config.get('network')
            self.mnemonic_next_index = config.get('mnemonic_next_index')
            self.first_public_key = config.get('first_public_key')
        else:
            raise OperatorConfigException(
                'Config for selected network does not exist. Please run "init" command.'
            )
        self._validate(mnemonic)

    def save(self, network: str, mnemonic: str, mnemonic_next_index: int = 0) -> None:
        self.network = network
        self.mnemonic_next_index = mnemonic_next_index
        self.first_public_key = CredentialManager.generate_credential_first_public_key(
            self.network, mnemonic
        )

        self._validate()
        config = {
            'network': self.network,
            'mnemonic_next_index': self.mnemonic_next_index,
            'first_public_key': self.first_public_key,
        }
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with self.config_path.open('w') as f:
            json.dump(config, f)

    def increment_mnemonic_index(self, count: int) -> None:
        self.mnemonic_next_index += count
        self._validate()
        config = {
            'network': self.network,
            'mnemonic_next_index': self.mnemonic_next_index,
            'first_public_key': self.first_public_key,
        }
        with self.config_path.open('w') as f:
            json.dump(config, f)

    def is_network_config_exists(self, network: str) -> bool:
        config_path = self.root_dir / network / 'config.json'
        return config_path.is_file()

    def _validate(self, mnemonic: str | None = None) -> None:
        """Validates the loaded configuration data."""
        if not self.network:
            raise OperatorConfigException('Network is not set in vault configuration.')

        if self.network not in AVAILABLE_NETWORKS:
            raise OperatorConfigException(
                "Invalid 'network' in config."
                f'Expected one of {AVAILABLE_NETWORKS}, got {self.network}.'
            )

        if self.mnemonic_next_index is None:
            raise OperatorConfigException('mnemonic_next_index is not set in vault configuration.')

        if not isinstance(self.mnemonic_next_index, int):
            raise OperatorConfigException(
                'Expected "mnemonic_next_index" to be int, '
                f'got {type(self.mnemonic_next_index).__name__}.'
            )

        if mnemonic and self.first_public_key:
            first_public_key = CredentialManager.generate_credential_first_public_key(
                self.network, mnemonic
            )
            if first_public_key != self.first_public_key:
                raise OperatorConfigException(
                    'Invalid mnemonic. Please use mnemonic generated with "init" command.'
                )

        if not self.first_public_key:
            raise OperatorConfigException('first_public_key is not set in vault configuration.')

        if not isinstance(self.first_public_key, str):
            raise OperatorConfigException(
                'Expected "first_public_key" to be str, '
                f'got {type(self.first_public_key).__name__}.'
            )

        if not re.match('^0x[0-9a-fA-F]{96}$', self.first_public_key):
            raise OperatorConfigException(
                "Invalid 'first_public_key'. Expected a 98-character hexadecimal string."
            )
