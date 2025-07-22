# pylint: disable=unused-argument
import re

import click
from eth_typing import ChecksumAddress
from eth_utils import is_address, to_checksum_address

from src.common.language import validate_mnemonic as verify_mnemonic


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
