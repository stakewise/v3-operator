import re

import click
from eth_utils import is_address, to_checksum_address

from src.common.language import validate_mnemonic as verify_mnemonic


# pylint: disable-next=unused-argument
def validate_mnemonic(ctx, param, value):
    value = value.replace('"', '')
    return verify_mnemonic(value)


# pylint: disable-next=unused-argument
def validate_eth_address(ctx, param, value):
    if not value:
        return None
    try:
        if is_address(value):
            return to_checksum_address(value)
    except ValueError:
        pass

    raise click.BadParameter('Invalid Ethereum address')


# pylint: disable-next=unused-argument
def validate_db_uri(ctx, param, value):
    pattern = re.compile(r'.+:\/\/.+:.*@.+\/.+')
    if not pattern.match(value):
        raise click.BadParameter('Invalid database connection string')
    return value

def validate_dappnode_execution_endpoints(ctx, param, value):
    dappnode = ctx.params.get('dappnode')
    if dappnode and not value:
        raise click.MissingParameter(ctx=ctx, param=param, message="Execution endpoints are required when --dappnode is set.")
    return value