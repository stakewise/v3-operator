import json
import re
import shutil
from pathlib import Path

import click
from eth_typing import HexAddress
from web3 import Web3

from src.common.credentials import CredentialManager
from src.config.networks import AVAILABLE_NETWORKS


class VaultConfig:
    network: str = ''
    mnemonic_next_index: int = 0
    first_public_key: str | None = None

    def __init__(
        self,
        vault: HexAddress,
        data_dir: Path,
    ):
        self.vault = Web3.to_checksum_address(vault)
        self.vault_dir = Path(data_dir) / vault.lower()
        self.config_path = self.vault_dir / 'config.json'

    @property
    def exists(self) -> bool:
        return self.config_path.is_file()

    @property
    def tmp_vault_dir(self) -> Path:
        return self.vault_dir / '.tmp'

    def create_tmp_dir(self) -> None:
        self.tmp_vault_dir.mkdir(parents=True, exist_ok=True)

    def remove_tmp_dir(self) -> None:
        shutil.rmtree(self.tmp_vault_dir)

    def load(self, mnemonic: str | None = None) -> None:
        if self.config_path.is_file():
            with self.config_path.open('r') as f:
                config = json.load(f)
            self.network = config.get('network')
            self.mnemonic_next_index = config.get('mnemonic_next_index')
            self.first_public_key = config.get('first_public_key')
        else:
            raise click.ClickException(
                f'Config for vault {self.vault} does not exist. Please run "init" command.'
            )
        self._validate(mnemonic)

    def save(self, network: str, mnemonic: str, mnemonic_next_index: int = 0) -> None:
        self.network = network
        self.mnemonic_next_index = mnemonic_next_index
        self.first_public_key = CredentialManager.generate_credential_first_public_key(
            self.network, self.vault, mnemonic
        )

        self._validate()
        config = {
            'network': self.network,
            'mnemonic_next_index': self.mnemonic_next_index,
            'first_public_key': self.first_public_key,
        }
        self.vault_dir.mkdir(parents=True, exist_ok=True)
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

    def _validate(self, mnemonic: str | None = None) -> None:
        """Validates the loaded configuration data."""
        if not self.network:
            raise click.ClickException('Network is not set in vault configuration.')

        if self.network not in AVAILABLE_NETWORKS:
            raise click.ClickException(
                "Invalid 'network' in config."
                f'Expected one of {AVAILABLE_NETWORKS}, got {self.network}.'
            )

        if self.mnemonic_next_index is None:
            raise click.ClickException('mnemonic_next_index is not set in vault configuration.')

        if not isinstance(self.mnemonic_next_index, int):
            raise click.ClickException(
                'Expected "mnemonic_next_index" to be int, '
                f'got {type(self.mnemonic_next_index).__name__}.'
            )

        if mnemonic and self.first_public_key:
            first_public_key = CredentialManager.generate_credential_first_public_key(
                self.network, self.vault, mnemonic
            )
            if first_public_key != self.first_public_key:
                raise click.ClickException(
                    'Invalid mnemonic. Please use mnemonic generated with "init" command.'
                )

        if not self.first_public_key:
            raise click.ClickException('first_public_key is not set in vault configuration.')

        if not isinstance(self.first_public_key, str):
            raise click.ClickException(
                'Expected "first_public_key" to be str, '
                f'got {type(self.first_public_key).__name__}.'
            )

        if not re.match('^0x[0-9a-fA-F]{96}$', self.first_public_key):
            raise click.ClickException(
                "Invalid 'first_public_key'. Expected a 98-character hexadecimal string."
            )
