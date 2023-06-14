import json
import re
from pathlib import Path

import click
from eth_typing import HexAddress
from web3 import Web3

from src.config.settings import AVAILABLE_NETWORKS


class VaultConfig:
    network: str = ''
    mnemonic_next_index: int = 0
    first_public_key: str | None = None

    def __init__(
        self,
        data_dir: str,
        vault: HexAddress,
    ):
        self.vault = vault
        if data_dir:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = Path.home() / '.stakewise' / vault
        self.config_path = self.data_dir / 'config.json'

    @property
    def is_exist(self) -> bool:
        return self.config_path.is_file()

    def load(self):
        if self.config_path.is_file():
            with self.config_path.open('r') as f:
                config = json.load(f)
            self.vault = config.get('vault')
            self.network = config.get('network')
            self.mnemonic_next_index = config.get('mnemonic_next_index')
            self.first_public_key = config.get('first_public_key')
        else:
            raise click.ClickException(f'{self.config_path} is not a file')
        self._validate()

    def save(
        self,
        network: str = '',
        mnemonic_next_index: int = 0,
        first_public_key: str | None = None
     ):
        config = {
            'vault': self.vault,
            'network': network,
            'mnemonic_next_index': mnemonic_next_index,
            'first_public_key': first_public_key,
        }

        self._validate()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with self.config_path.open('w') as f:
            json.dump(config, f)

    def update(self, network=None, mnemonic_next_index=None, first_public_key=None):
        if network is not None:
            self.network = network
        if mnemonic_next_index is not None:
            self.mnemonic_next_index = mnemonic_next_index
        if first_public_key is not None:
            self.first_public_key = first_public_key
        self._validate()
        config = {
            'network': self.network,
            'mnemonic_next_index': self.mnemonic_next_index,
            'first_public_key': self.first_public_key,
        }
        with self.config_path.open('w') as f:
            json.dump(config, f)

    def _validate(self):
        """Validates the loaded configuration data."""
        if not self.vault:
            raise click.ClickException('Vault is not set in the configuration.')

        if Web3.is_checksum_address(self.vault):
            raise click.ClickException('Invalid vault address.')

        if not self.network:
            raise click.ClickException('Network is not set in the configuration.')

        if self.network not in AVAILABLE_NETWORKS:
            raise click.ClickException(
                "Invalid 'network' in config."
                f'Expected one of {AVAILABLE_NETWORKS}, got {self.network}.'
            )

        if self.mnemonic_next_index is None:
            raise click.ClickException('mnemonic_next_index is not set in the configuration.')

        if not isinstance(self.mnemonic_next_index, int):
            raise click.ClickException(
                'Expected "mnemonic_next_index" to be int, '
                f'got {type(self.mnemonic_next_index).__name__}.'
            )

        if not self.first_public_key:
            raise click.ClickException('first_public_key is not set in the configuration.')

        if not isinstance(self.first_public_key, str):
            raise click.ClickException(
                'Expected "first_public_key" to be str, '
                f'got {type(self.first_public_key).__name__}.'
            )

        if not re.match('^0x[0-9a-fA-F]{96}$', self.first_public_key):
            raise click.ClickException(
                "Invalid 'first_public_key'. Expected a 98-character hexadecimal string."
            )
