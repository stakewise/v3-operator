import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from web3.types import Gwei

from src.commands.start.base import start_base
from src.commands.start.common_option import add_common_options, start_common_options
from src.common.startup_check import check_hardware_requirements
from src.common.typings import ValidatorType
from src.common.utils import log_verbose
from src.config.config import OperatorConfig
from src.config.settings import Features, settings

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
@click.option(
    '--run-nodes',
    is_flag=True,
    envvar='RUN_NODES',
    help='If set, the operator will also start and manage local consensus, execution '
    'and validator nodes. Default is false.',
)
@click.option(
    '--no-confirm',
    is_flag=True,
    help='Skips confirmation messages when provided. Default is false.',
)
@add_common_options(start_common_options)
@click.command(help='Start operator service')
# pylint: disable-next=too-many-arguments,too-many-locals
def start_local(
    vault: ChecksumAddress,
    consensus_endpoints: str,
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    harvest_vault: bool,
    claim_fee_splitter: bool,
    disable_withdrawals: bool,
    disable_validators_registration: bool,
    disable_validators_funding: bool,
    verbose: bool,
    enable_metrics: bool,
    metrics_host: str,
    metrics_port: int,
    metrics_prefix: str,
    validator_type: ValidatorType,
    data_dir: str,
    log_level: str,
    log_format: str,
    keystores_dir: str | None,
    keystores_password_file: str | None,
    wallet_file: str | None,
    wallet_password_file: str | None,
    max_fee_per_gas_gwei: int | None,
    database_dir: str | None,
    concurrency: int | None,
    min_deposit_amount_gwei: int,
    vault_min_balance_gwei: int,
    max_validator_balance_gwei: int | None,
    min_deposit_delay: int,
    max_withdrawal_request_fee_gwei: int,
    no_confirm: bool,
    run_nodes: bool,
) -> None:
    operator_config = OperatorConfig(vault, Path(data_dir))
    operator_config.load()

    features = Features(
        harvest_vault=harvest_vault,
        claim_fee_splitter=claim_fee_splitter,
        disable_withdrawals=disable_withdrawals,
        disable_validators_registration=disable_validators_registration,
        disable_validators_funding=disable_validators_funding,
        enable_metrics=enable_metrics,
    )
    settings.set(
        vault=vault,
        vault_dir=operator_config.vault_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_endpoint=graph_endpoint,
        features=features,
        verbose=verbose,
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
        vault_min_balance_gwei=Gwei(vault_min_balance_gwei),
        max_validator_balance_gwei=(
            Gwei(max_validator_balance_gwei) if max_validator_balance_gwei else None
        ),
        min_deposit_delay=min_deposit_delay,
        max_withdrawal_request_fee_gwei=Gwei(max_withdrawal_request_fee_gwei),
        run_nodes=run_nodes,
        nodes_dir=Path(data_dir) / operator_config.network / 'nodes',
    )

    if settings.run_nodes:
        click.echo('Checking hardware requirements...')
        check_hardware_requirements(
            data_dir=Path(data_dir), network=settings.network, no_confirm=no_confirm
        )

    try:
        asyncio.run(start_base())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)
