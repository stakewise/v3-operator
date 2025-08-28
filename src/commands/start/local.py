import asyncio
import logging
import sys

import click
from eth_utils import to_checksum_address
from web3.types import Gwei

from src.commands.start.base import load_operator_config, start_base
from src.commands.start.common_option import add_common_options, start_common_options
from src.common.typings import ValidatorType
from src.common.utils import log_verbose
from src.config.settings import settings

logger = logging.getLogger(__name__)


@click.option(
    '--keystores-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='KEYSTORES_PASSWORD_FILE',
    help='Absolute path to the password file for decrypting keystores. '
    'Default is the file generated with "create-keys" command.',
)
@click.option(
    '--keystores-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='KEYSTORES_DIR',
    help='Absolute path to the directory with all the encrypted keystores. '
    'Default is the directory generated with "create-keys" command.',
)
@add_common_options(start_common_options)
@click.command(help='Start operator service')
# pylint: disable-next=too-many-arguments,too-many-locals
def start_local(
    vaults: str,
    consensus_endpoints: str,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    harvest_vault: bool,
    claim_fee_splitter: bool,
    disable_withdrawals: bool,
    verbose: bool,
    enable_metrics: bool,
    metrics_host: str,
    metrics_port: int,
    metrics_prefix: str,
    validator_type: ValidatorType,
    data_dir: str,
    log_level: str,
    log_format: str,
    network: str | None,
    keystores_dir: str | None,
    keystores_password_file: str | None,
    wallet_file: str | None,
    wallet_password_file: str | None,
    max_fee_per_gas_gwei: int | None,
    database_dir: str | None,
    concurrency: int | None,
    min_deposit_amount_gwei: int,
    no_confirm: bool,
) -> None:
    vault_addresses = [to_checksum_address(address) for address in vaults.split(',')]
    operator_config = load_operator_config(
        vaults=vault_addresses,
        data_dir=data_dir,
        network=network,
        no_confirm=no_confirm,
    )

    settings.set(
        vaults=vault_addresses,
        data_dir=operator_config.data_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_endpoint=graph_endpoint,
        harvest_vault=harvest_vault,
        claim_fee_splitter=claim_fee_splitter,
        disable_withdrawals=disable_withdrawals,
        verbose=verbose,
        enable_metrics=enable_metrics,
        metrics_host=metrics_host,
        metrics_port=metrics_port,
        metrics_prefix=metrics_prefix,
        network=operator_config.network,
        validator_type=validator_type,
        keystores_dir=keystores_dir,
        keystores_password_file=keystores_password_file,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        database_dir=database_dir,
        log_level=log_level,
        log_format=log_format,
        concurrency=concurrency,
        min_deposit_amount_gwei=Gwei(min_deposit_amount_gwei),
    )

    try:
        asyncio.run(start_base())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)
