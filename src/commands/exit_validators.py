import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import ChecksumAddress, HexStr
from web3.types import Gwei

from src.common.clients import setup_clients
from src.common.consensus import get_chain_justified_head
from src.common.contracts import VaultContract
from src.common.execution import get_execution_request_fee
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.startup_check import check_validators_manager, check_vault_version
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address, validate_indexes
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import MAX_WITHDRAWAL_REQUEST_FEE, settings
from src.validators.consensus import EXITING_STATUSES, fetch_consensus_validators
from src.validators.typings import ConsensusValidator
from src.withdrawals.execution import submit_withdraw_validators

logger = logging.getLogger(__name__)


@click.option(
    '--network',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
    envvar='NETWORK',
    help='The network of the vault. Default is the network specified at "init" command.',
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the config data is placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--indexes',
    type=str,
    help='Comma separated list of indexes of validators to exit.',
    callback=validate_indexes,
)
@click.option(
    '--count',
    help='The number of validators to exit. Default is all the active validators.',
    type=click.IntRange(min=1),
)
@click.option(
    '--consensus-endpoints',
    help='Comma separated list of API endpoints for consensus nodes',
    prompt='Enter the comma separated list of API endpoints for consensus nodes',
    envvar='CONSENSUS_ENDPOINTS',
    type=str,
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter the comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--log-level',
    type=click.Choice(
        LOG_LEVELS,
        case_sensitive=False,
    ),
    default='INFO',
    envvar='LOG_LEVEL',
    help='The log level.',
)
@click.command(help='Performs a voluntary exit for active vault validators.')
# pylint: disable-next=too-many-arguments
def exit_validators(
    network: str,
    vault: ChecksumAddress,
    indexes: list[int],
    count: int | None,
    consensus_endpoints: str,
    execution_endpoints: str,
    data_dir: str,
    verbose: bool,
    log_level: str,
) -> None:
    if all([indexes, count]):
        raise click.ClickException('Please provide either --indexes or --count, not both.')
    operator_config = OperatorConfig(Path(data_dir))
    operator_config.load(network=network)

    settings.set(
        vaults=[vault],
        network=network,
        data_dir=operator_config.data_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        verbose=verbose,
        log_level=log_level,
    )
    try:
        asyncio.run(
            main(
                vault_address=vault,
                indexes=indexes,
                count=count,
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(vault_address: ChecksumAddress, count: int | None, indexes: list[int]) -> None:
    setup_logging()
    await setup_clients()

    await check_vault_version()
    await check_validators_manager(vault_address)

    withdrawal_request_fee = await get_execution_request_fee(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
    )
    if withdrawal_request_fee > MAX_WITHDRAWAL_REQUEST_FEE:
        raise click.ClickException(
            'Validator exits are skipped due to high withdrawal fee. '
            f'The current fee is {withdrawal_request_fee}.'
        )

    chain_head = await get_chain_justified_head()
    max_activation_epoch = chain_head.epoch - settings.network_config.SHARD_COMMITTEE_PERIOD

    logger.info('Fetching vault validators...')
    vault_contract = VaultContract(vault_address)
    public_keys = await vault_contract.get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=chain_head.block_number,
    )
    if indexes:
        exiting_validators = await _check_exiting_validators(
            indexes=indexes,
            vault_public_keys=public_keys,
            max_activation_epoch=max_activation_epoch,
        )
    else:
        exiting_validators = await _get_exiting_validators(
            vault_public_keys=public_keys, max_activation_epoch=max_activation_epoch
        )

    if not exiting_validators:
        raise click.ClickException('No active validators found')

    if count:
        exiting_validators = exiting_validators[:count]

    click.confirm(
        f'Are you sure you want to exit {len(exiting_validators)} validators '
        f'with indexes: {', '.join(str(x.index) for x in exiting_validators)}?',
        abort=True,
    )
    tx_hash = await submit_withdraw_validators(
        vault_address=vault_address,
        withdrawals={val.public_key: Gwei(0) for val in exiting_validators},
        tx_fee=withdrawal_request_fee,
    )
    if tx_hash:
        click.secho(
            f'Validators {', '.join(str(val.index) for val in exiting_validators)} '
            f'exits successfully initiated',
            bold=True,
            fg='green',
        )


async def _get_exiting_validators(
    max_activation_epoch: int, vault_public_keys: list[HexStr]
) -> list[ConsensusValidator]:
    """Fetch consensus validators that are eligible for exit."""
    consensus_validators = await fetch_consensus_validators(vault_public_keys)
    can_be_exited_validators = []
    for validator in consensus_validators:
        if validator.activation_epoch > max_activation_epoch:
            continue
        if validator.status in EXITING_STATUSES:
            continue
        can_be_exited_validators.append(validator)
    can_be_exited_validators.sort(key=lambda val: val.activation_epoch)
    return can_be_exited_validators


async def _check_exiting_validators(
    indexes: list[int], vault_public_keys: list[HexStr], max_activation_epoch: int
) -> list[ConsensusValidator]:
    """Validate that validators with provided indexes are eligible for exit."""
    consensus_validators = await fetch_consensus_validators([str(i) for i in indexes])
    if not consensus_validators:
        raise click.ClickException('No validators found with the provided indexes.')
    public_keys = set(vault_public_keys)
    for validator in consensus_validators:
        if validator.public_key not in public_keys:
            raise click.ClickException(
                f'Validator with index {validator.index} is not registered in the vault.'
            )
        if validator.activation_epoch > max_activation_epoch:
            raise click.ClickException(
                f'Validator with index {validator.index} is too new to exit.'
            )
        if validator.status in EXITING_STATUSES:
            raise click.ClickException(
                f'Validator with index {validator.index} is already exiting or exited.'
            )
    consensus_validators.sort(key=lambda val: val.activation_epoch)
    return consensus_validators
