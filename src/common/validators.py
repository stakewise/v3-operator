import re

import click
from eth_typing import HexStr
from eth_utils import is_address, is_hexstr, to_checksum_address

from src.common.language import validate_mnemonic as verify_mnemonic
from src.config.settings import DEFAULT_MIN_DEPOSIT_AMOUNT


# pylint: disable-next=unused-argument
def validate_mnemonic(ctx, param, value):  # type: ignore
    value = value.replace('"', '')
    return verify_mnemonic(value)


# pylint: disable-next=unused-argument
def validate_eth_address(ctx, param, value):  # type: ignore
    if not value:
        return None
    try:
        if is_address(value):
            return to_checksum_address(value)
    except ValueError:
        pass

    raise click.BadParameter('Invalid Ethereum address')


# pylint: disable-next=unused-argument
def validate_eth_addresses(ctx, param, value):  # type: ignore
    if not value:
        return None
    try:
        for address in value.split(','):
            if not is_address(address):
                raise click.BadParameter('Invalid Ethereum address')
    except ValueError:
        pass

    return [to_checksum_address(address) for address in value.split(',')]


# pylint: disable-next=unused-argument
def validate_db_uri(ctx, param, value):  # type: ignore
    pattern = re.compile(r'.+:\/\/.+:.*@.+\/.+')
    if not pattern.match(value):
        raise click.BadParameter('Invalid database connection string')
    return value


def validate_dappnode_execution_endpoints(ctx, param, value):  # type: ignore
    dappnode = ctx.params.get('dappnode')
    if dappnode and not value:
        raise click.MissingParameter(
            ctx=ctx, param=param, message='Execution endpoints are required when --dappnode is set.'
        )

    return value


# pylint: disable-next=unused-argument
def validate_min_deposit_amount(ctx, param, value):  # type: ignore
    if value < DEFAULT_MIN_DEPOSIT_AMOUNT:
        raise click.BadParameter(
            f'min-deposit-amount must be greater than or equal to {DEFAULT_MIN_DEPOSIT_AMOUNT} GWEI'
        )

    return value


# pylint: disable-next=unused-argument
def validate_public_key(ctx, param, value):  # type: ignore
    if not value:
        return None
    if not _is_public_key(value):
        raise click.BadParameter('Invalid validator public key')

    return value


# pylint: disable-next=unused-argument
def validate_public_keys(ctx, param, value):  # type: ignore
    if not value:
        return None
    for key in value.split(','):
        if not _is_public_key(key):
            raise click.BadParameter('Invalid validator public key')

    return [HexStr(address) for address in value.split(',')]


# pylint: disable-next=unused-argument
def validate_public_keys_file(ctx, param, value):  # type: ignore
    if not value:
        return None
    with open(value, 'r', encoding='utf-8') as f:
        for line in f:
            key = line.strip()
            if not _is_public_key(key):
                raise click.BadParameter(f'Invalid validator public key: {key}')

    return value


def _is_public_key(value: str) -> bool:
    public_key_length = 98
    return is_hexstr(value) and len(value) == public_key_length
