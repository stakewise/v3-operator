import json
from pathlib import Path

import click
import requests
from eth_typing import HexAddress

from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import AVAILABLE_NETWORKS, DEFAULT_NETWORK, settings


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='The vault address.',
    type=str,
    callback=validate_eth_address,
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
    vault: HexAddress,
    network: str,
    pool_tag: str,
    token: str,
    data_dir: str,
) -> None:
    vault_config = VaultConfig(vault, Path(data_dir))
    vault_config.load()

    settings.set(
        vault=vault,
        vault_dir=vault_config.vault_dir,
        network=network,
        execution_endpoints='',
        consensus_endpoints='',
    )
    click.secho('Rated self report')

    validators = fetch_validators(vault, settings.stakewise_api_url)
    if not validators:
        click.secho('No validators found or failed to fetch validators.', bold=True, fg='red')
        return

    if len(validators) > 1000:
        click.secho(
            'You have more than 1,000 validators. Please split them into multiple requests.',
            bold=True,
            fg='red',
        )
        return

    payload = {'validators': validators, 'poolTag': pool_tag}

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'X-Rated-Network': network,
    }

    response = requests.post(
        f'{settings.rated_api_url}/v0/selfReports/validators',
        headers=headers,
        data=json.dumps(payload),
        timeout=15,
    )

    if response.status_code == 201:
        click.secho('Successfully reported validators.', bold=True, fg='green')
        click.secho(f'{response.json}')
    else:
        click.secho(
            (
                f'Failed to report validators. Status code: {response.status_code}, '
                f'Response: {response.text}'
            ),
            bold=True,
            fg='red',
        )


def fetch_validators(vault_address: str, api_url: str) -> list:
    url = api_url
    query = {
        'query': """
        query Validators {
          vaultValidators(
            vaultAddress: "%s"
            statusIn: "active_ongoing"
          ) {
            publicKey
          }
        }
        """
        % vault_address
    }

    response = requests.post(
        url,
        json=query,
        headers={'Content-Type': 'application/json'},
        timeout=15,
    )

    if response.status_code == 200:
        data = response.json()
        return [
            validator['publicKey'] for validator in data.get('data', {}).get('vaultValidators', [])
        ]

    click.secho(
        (
            f'Failed to fetch validators. Status code: {response.status_code}, '
            f'Response: {response.text}'
        ),
        bold=True,
        fg='red',
    )
    return []
