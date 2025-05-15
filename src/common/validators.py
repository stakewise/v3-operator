import re

import click
from eth_utils import is_address, to_checksum_address

from src.common.language import validate_mnemonic as verify_mnemonic


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
