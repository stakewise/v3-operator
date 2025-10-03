import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from web3.types import Gwei

from src.commands.start.base import start_base
from src.commands.start.common_option import add_common_options, start_common_options
from src.common.typings import ValidatorType
from src.common.utils import log_verbose
from src.config.config import OperatorConfig
from src.config.settings import settings

logger = logging.getLogger(__name__)


@click.option(
    '--remote-signer-url',
    type=str,
    envvar='REMOTE_SIGNER_URL',
    help='The base URL of the remote signer, e.g. https://signer:9000',
    prompt='Enter the base URL of the remote signer (e.g. https://signer:9000)',
)
@add_common_options(start_common_options)
@click.command(help='Start operator service with the remote signer integration.')
# pylint: disable-next=too-many-arguments,too-many-locals
def start_remote_signer(
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
    remote_signer_url: str | None,
    wallet_file: str | None,
    wallet_password_file: str | None,
    max_fee_per_gas_gwei: int | None,
    database_dir: str | None,
    concurrency: int | None,
    min_deposit_amount_gwei: int,
    max_validator_balance_gwei: int | None,
    min_deposit_delay: int,
) -> None:
    operator_config = OperatorConfig(vault, Path(data_dir))
    operator_config.load()

    settings.set(
        vault=vault,
        vault_dir=operator_config.vault_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_endpoint=graph_endpoint,
        harvest_vault=harvest_vault,
        claim_fee_splitter=claim_fee_splitter,
        disable_withdrawals=disable_withdrawals,
        disable_validators_registration=disable_validators_registration,
        disable_validators_funding=disable_validators_funding,
        verbose=verbose,
        enable_metrics=enable_metrics,
        metrics_host=metrics_host,
        metrics_port=metrics_port,
        metrics_prefix=metrics_prefix,
        network=operator_config.network,
        validator_type=validator_type,
        remote_signer_url=remote_signer_url,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        database_dir=database_dir,
        log_level=log_level,
        log_format=log_format,
        concurrency=concurrency,
        min_deposit_amount_gwei=Gwei(min_deposit_amount_gwei),
        max_validator_balance_gwei=(
            Gwei(max_validator_balance_gwei) if max_validator_balance_gwei else None
        ),
        min_deposit_delay=min_deposit_delay,
    )

    try:
        asyncio.run(start_base())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)
