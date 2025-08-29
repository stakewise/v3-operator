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
from src.config.networks import NETWORKS
from src.config.settings import RelayerTypes, ValidatorsRegistrationMode, settings

logger = logging.getLogger(__name__)


# Special value used to dynamically determine option value
AUTO = 'AUTO'


@click.option(
    '--relayer-type',
    type=click.Choice(
        [RelayerTypes.DEFAULT, RelayerTypes.DVT],
        case_sensitive=False,
    ),
    default=RelayerTypes.DEFAULT,
    help='Relayer type.',
    envvar='RELAYER_TYPE',
)
@click.option(
    '--relayer-endpoint',
    type=str,
    help='Relayer endpoint.',
    prompt='Enter the relayer endpoint',
    envvar='RELAYER_ENDPOINT',
    default=AUTO,
)
@add_common_options(start_common_options)
@click.command(help='Start operator service in API mode')
# pylint: disable-next=too-many-arguments,too-many-locals
def start_relayer(
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
    min_deposit_amount_gwei: int,
    min_deposit_delay: int,
    data_dir: str,
    log_level: str,
    log_format: str,
    network: str | None,
    wallet_file: str | None,
    wallet_password_file: str | None,
    max_fee_per_gas_gwei: int | None,
    database_dir: str | None,
    relayer_type: str,
    relayer_endpoint: str,
    no_confirm: bool,
) -> None:
    vault_addresses = [to_checksum_address(address) for address in vaults.split(',')]

    operator_config = load_operator_config(
        vaults=vault_addresses,
        data_dir=data_dir,
        network=network,
        no_confirm=no_confirm,
    )
    network = operator_config.network
    if relayer_endpoint == AUTO and relayer_type == RelayerTypes.DVT:
        network_config = NETWORKS[network]
        relayer_endpoint = network_config.DEFAULT_DVT_RELAYER_ENDPOINT

    if relayer_endpoint == AUTO and relayer_type == RelayerTypes.DEFAULT:
        raise click.ClickException('Relayer endpoint must be specified for default relayer type')

    validators_registration_mode = ValidatorsRegistrationMode.API

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
        validator_type=validator_type,
        network=network,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        max_fee_per_gas_gwei=max_fee_per_gas_gwei,
        database_dir=database_dir,
        log_level=log_level,
        log_format=log_format,
        relayer_type=relayer_type,
        relayer_endpoint=relayer_endpoint,
        validators_registration_mode=validators_registration_mode,
        min_deposit_amount_gwei=Gwei(min_deposit_amount_gwei),
        min_deposit_delay=min_deposit_delay,
    )

    try:
        asyncio.run(start_base())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)
