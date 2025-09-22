# pylint: disable=unused-argument
import re
from pathlib import Path

import click
from eth_typing import ChecksumAddress, HexStr
from eth_utils import is_address, is_hexstr, to_checksum_address
from web3.types import Gwei

from src.common.language import validate_mnemonic as verify_mnemonic
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI


def validate_network(ctx: click.Context, param: click.Parameter, value: str) -> str | None:
    if value:
        return value
    data_dir = ctx.params.get('data_dir') or str(Path.home() / '.stakewise')
    root_dir = Path(data_dir)
    try:
        network = _guess_network(root_dir)
    except MultipleNetworksFound:
        network = click.prompt(
            'Enter the network of your vault',
            type=click.Choice(
                AVAILABLE_NETWORKS,
                case_sensitive=False,
            ),
        )
    return network


def validate_mnemonic(ctx: click.Context, param: click.Parameter, value: str) -> str:
    value = value.replace('"', '')
    return verify_mnemonic(value)


def validate_eth_address(
    ctx: click.Context, param: click.Parameter, value: str | None
) -> ChecksumAddress | None:
    if not value:
        return None
    try:
        if is_address(value):
            return to_checksum_address(value)
    except ValueError:
        pass

    raise click.BadParameter('Invalid Ethereum address')


def validate_eth_addresses(
    ctx: click.Context, param: click.Parameter, value: str | None
) -> str | None:
    if not value:
        return None
    try:
        for address in value.split(','):
            if not is_address(address):
                raise click.BadParameter('Invalid Ethereum address')
    except ValueError:
        pass

    return value


def validate_db_uri(ctx: click.Context, param: click.Parameter, value: str) -> str:
    pattern = re.compile(r'.+:\/\/.+:.*@.+\/.+')
    if not pattern.match(value):
        raise click.BadParameter('Invalid database connection string')
    return value


def validate_dappnode_execution_endpoints(
    ctx: click.Context, param: click.Parameter, value: str
) -> str | None:
    dappnode = ctx.params.get('dappnode')
    if dappnode and not value:
        raise click.MissingParameter(
            ctx=ctx, param=param, message='Execution endpoints are required when --dappnode is set.'
        )

    return value


def validate_min_deposit_amount_gwei(
    ctx: click.Context, param: click.Parameter, value: int
) -> Gwei | None:
    value = Gwei(value)
    if value < DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI:
        raise click.BadParameter(
            f'min-deposit-amount-gwei must be greater than or equal to '
            f'{DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI} Gwei'
        )

    return value


def validate_public_key(ctx: click.Context, param: click.Parameter, value: str) -> str | None:
    if not value:
        return None
    if not _is_public_key(value):
        raise click.BadParameter('Invalid validator public key')

    return value


def validate_public_keys(
    ctx: click.Context, param: click.Parameter, value: str
) -> list[HexStr] | None:
    if not value:
        return None
    for key in value.split(','):
        if not _is_public_key(key):
            raise click.BadParameter('Invalid validator public key')

    return [HexStr(address) for address in value.split(',')]


def validate_public_keys_file(ctx: click.Context, param: click.Parameter, value: str) -> str | None:
    if not value:
        return None
    with open(value, 'r', encoding='utf-8') as f:
        for line in f:
            key = line.strip()
            if not _is_public_key(key):
                raise click.BadParameter(f'Invalid validator public key: {key}')

    return value


def validate_indexes(ctx: click.Context, param: click.Parameter, value: str) -> list[int] | None:
    if not value:
        return None
    for key in value.split(','):
        try:
            if int(key) < 0:
                raise click.BadParameter('Invalid validator index')
        except ValueError as e:
            raise click.BadParameter('Indexes must be integers') from e
    return [int(i) for i in value.split(',')]


def _is_public_key(value: str) -> bool:
    public_key_length = 98
    return is_hexstr(value) and len(value) == public_key_length


class MultipleNetworksFound(Exception):
    pass


def _guess_network(root_dir: Path) -> str | None:
    dirs = [f for f in root_dir.iterdir() if f.is_dir()]
    network_directory_names = [d.name for d in dirs if d.name in AVAILABLE_NETWORKS]
    if len(dirs) and len(network_directory_names) == 1:
        return network_directory_names[0]

    if len(dirs) and len(network_directory_names) > 1:
        raise MultipleNetworksFound
    return None
