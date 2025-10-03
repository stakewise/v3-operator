# pylint: disable=unused-argument
import re

import click
from eth_typing import ChecksumAddress, HexStr
from eth_utils import is_address, is_hexstr, to_checksum_address
from web3 import Web3

from src.common.language import validate_mnemonic as verify_mnemonic
from src.config.settings import (
    MAX_EFFECTIVE_BALANCE,
    MAX_EFFECTIVE_BALANCE_GWEI,
    MIN_ACTIVATION_BALANCE,
    MIN_ACTIVATION_BALANCE_GWEI,
)


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


def validate_max_validator_balance_gwei(
    ctx: click.Context, param: click.Parameter, value: int
) -> int | None:
    if not value:
        return None
    if value < MIN_ACTIVATION_BALANCE_GWEI:
        raise click.BadParameter(
            f'max-validator-balance-gwei must be greater than or equal to '
            f'{MIN_ACTIVATION_BALANCE_GWEI} Gwei '
            f'({Web3.from_wei(MIN_ACTIVATION_BALANCE, 'ether')} ETH)'
        )
    if value > MAX_EFFECTIVE_BALANCE_GWEI:
        raise click.BadParameter(
            f'max-validator-balance-gwei must be less than or equal to '
            f'{MAX_EFFECTIVE_BALANCE_GWEI} Gwei '
            f'({Web3.from_wei(MAX_EFFECTIVE_BALANCE, 'ether')} ETH)'
        )
    return value


def _is_public_key(value: str) -> bool:
    public_key_length = 98
    return is_hexstr(value) and len(value) == public_key_length
