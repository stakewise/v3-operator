import asyncio
from pathlib import Path

import click
import requests
from eth_typing import ChecksumAddress

from src.common.graph import GraphClient
from src.common.validators import validate_eth_addresses
from src.common.vault_config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS, RATED_NETWORKS
from src.config.settings import DEFAULT_NETWORK, settings


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--vaults',
    prompt='Enter your vault address',
    help='The vault addresses.',
    type=str,
    callback=validate_eth_addresses,
)
@click.option(
    '--network',
    default=DEFAULT_NETWORK,
    help='The network of your vault.',
    prompt='Enter the network name',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.option(
    '--pool-tag',
    default='',
    help='The pool name listed on the Explorer.',
    prompt='Enter the pool tag (if any)',
    type=str,
)
@click.option(
    '--token',
    prompt='Enter your OAuth token',
    help='OAuth token for authorization.',
    type=str,
)
@click.command(help='Self-report your validators to the Rated Network.')
def rated_self_report(
    vaults: list[ChecksumAddress],
    network: str,
    pool_tag: str,
    token: str,
    data_dir: str,
) -> None:
    if network not in RATED_NETWORKS:
        click.secho(f'{network} network is not yet rated supported')
        return

    vault_config = OperatorConfig(Path(data_dir))
    vault_config.load()

    settings.set(
        vaults=vaults,
        config_dir=vault_config.config_dir,
        network=network,
        execution_endpoints='',
        consensus_endpoints='',
    )
    click.secho('Starting rated self report...')
    for vault in vaults:
        asyncio.run(_report_validators(vault, pool_tag, token, network))


async def _report_validators(
    vault: str,
    pool_tag: str,
    token: str,
    network: str,
) -> None:
    graph_client = GraphClient()
    validators = await graph_client.get_vault_validators(vault)
    if not validators:
        click.secho('No validators found or failed to fetch validators.', bold=True, fg='red')
        return

    chunk_size = 1000
    for i in range(0, len(validators), chunk_size):
        chunk = validators[i : i + chunk_size]

        payload = {'validators': chunk, 'poolTag': pool_tag}

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}',
            'X-Rated-Network': network,
        }

        response = requests.post(
            f'{settings.network_config.RATED_API_URL}/v0/selfReports/validators',
            headers=headers,
            json=payload,
            timeout=15,
        )

        if response.status_code == 201:
            click.secho(f'Successfully reported {len(chunk)} validators.', bold=True, fg='green')
        else:
            click.secho(
                (
                    f'Failed to report validators. Status code: {response.status_code}, '
                    f'Response: {response.text}'
                ),
                bold=True,
                fg='red',
            )
