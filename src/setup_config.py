from pathlib import Path

import click
from decouple import config as decouple_config

from src.common.config import VaultConfig
from src.config.settings import settings


def setup_config(*args, **kwargs) -> None:
    vault = kwargs.pop('vault', None) or decouple_config('VAULT', default='')
    network = kwargs.pop('network', None) or decouple_config('NETWORK', default='')

    data_dir = kwargs.pop('data_dir', None) or decouple_config('DATA_DIR', default='')
    config = VaultConfig(vault=vault, data_dir=data_dir)

    if not vault:
        raise click.ClickException('Please provide "vault" parameter.')
    if data_dir and not config.exists:
        raise click.ClickException(
            f'Empty data-dir. Please use data-dir provided for {vault} init command.'
        )

    if config.exists:
        config.load()

        if network and network != config.network:
            raise click.ClickException(
                f'Invalid vault network. Please use data-dir provided for {vault} init command.'
            )
        if not network:
            network = config.network
    else:
        if not network:
            raise click.ClickException('Please provide "network" parameter.')
    if data_dir:
        data_dir = Path(data_dir)
    settings.set(vault=vault, network=network, data_dir=data_dir, *args, **kwargs)  # type: ignore
