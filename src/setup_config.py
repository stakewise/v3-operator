from pathlib import Path

import click
from decouple import config as decouple_config

from src.common.config import VaultConfig
from src.config.settings import settings


def setup_config(*args, **kwargs) -> None:
    # Vault and network will be loaded from vault config if not passed another way.
    vault = kwargs.pop('vault', None) or decouple_config('VAULT_CONTRACT_ADDRESS', default='')
    network = kwargs.pop('network', None) or decouple_config('NETWORK', default='')

    data_dir = kwargs.pop('data_dir') or decouple_config('DATA_DIR', default='')
    config = VaultConfig(vault=vault, data_dir=data_dir)
    if config.exists:
        config.load()

        if vault and vault != config.vault:
            raise click.ClickException(
                f'Invalid vault address. Please use data-dir provided for {vault} init command.'
            )
        if not vault:
            vault = config.vault

        if network and network != config.network:
            raise click.ClickException(
                f'Invalid vault network. Please use data-dir provided for {vault} init command.'
            )
        if not network:
            network = config.network
    if data_dir:
        data_dir = Path(data_dir)
    settings.set(vault=vault, network=network, data_dir=data_dir, *args, **kwargs)  # type: ignore
