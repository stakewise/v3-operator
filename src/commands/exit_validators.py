import asyncio
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import close_clients, setup_clients
from src.common.consensus import get_chain_justified_head
from src.common.contracts import VaultContract
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.startup_check import check_validators_manager, check_vault_version
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address, validate_indexes
from src.common.withdrawals import get_withdrawal_request_fee
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS
from src.config.settings import DEFAULT_MAX_WITHDRAWAL_REQUEST_FEE_GWEI, settings
from src.validators.consensus import EXITING_STATUSES, fetch_consensus_validators
from src.validators.relayer import RelayerClient
from src.validators.typings import ConsensusValidator
from src.withdrawals.execution import submit_withdraw_validators

logger = logging.getLogger(__name__)


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the config data is placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--network',
    help='The network of the vault. Default is the network specified at "init" command.',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
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
    '--relayer-endpoint',
    type=str,
    help='Relayer endpoint.',
    envvar='RELAYER_ENDPOINT',
)
@click.option(
    '--max-withdrawal-request-fee-gwei',
    type=int,
    envvar='MAX_WITHDRAWAL_REQUEST_FEE_GWEI',
    help='The maximum withdrawal request fee in Gwei.',
    default=DEFAULT_MAX_WITHDRAWAL_REQUEST_FEE_GWEI,
    show_default=True,
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
@click.option(
    '--no-confirm',
    is_flag=True,
    help='Skips confirmation messages when provided. Default is false.',
)
@click.option(
    '--vault-first-block',
    type=int,
    envvar='VAULT_FIRST_BLOCK',
    help='The block number where the vault was created. Used to optimize fetching vault events.',
)
@click.command(help='Performs a voluntary exit for active vault validators.')
# pylint: disable-next=too-many-arguments,too-many-locals
def exit_validators(
    vault: ChecksumAddress,
    indexes: list[int],
    count: int | None,
    consensus_endpoints: str,
    execution_endpoints: str,
    max_withdrawal_request_fee_gwei: int,
    data_dir: str,
    network: str | None,
    verbose: bool,
    no_confirm: bool,
    log_level: str,
    relayer_endpoint: str | None,
    vault_first_block: BlockNumber | None,
) -> None:
    """
    Trigger vault validator exits via vault contract.
    To initiate a full validator exit, send a withdrawal request with a zero amount.
    """
    if all([indexes, count]):
        raise click.ClickException('Please provide either --indexes or --count, not both.')
    operator_config = OperatorConfig(vault, Path(data_dir))

    if network is None and not operator_config.exists:
        raise click.ClickException(
            'Either provide the network using --network option or run "init" command first.'
        )

    if network is None:
        operator_config.load()
        network = operator_config.network

    settings.set(
        vault=vault,
        vault_dir=operator_config.vault_dir,
        network=network,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        max_withdrawal_request_fee_gwei=Gwei(max_withdrawal_request_fee_gwei),
        relayer_endpoint=relayer_endpoint,
        verbose=verbose,
        log_level=log_level,
        vault_first_block=vault_first_block,
    )
    try:
        # Try-catch to enable async calls in test - an event loop
        #  will already be running in that case
        try:
            asyncio.get_running_loop()
            # we need to create a separate thread so we can block before returning
            with ThreadPoolExecutor(1) as pool:
                pool.submit(
                    lambda: asyncio.run(
                        main(
                            vault_address=vault,
                            indexes=indexes,
                            count=count,
                            no_confirm=no_confirm,
                        )
                    )
                ).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(
                    main(
                        vault_address=vault,
                        indexes=indexes,
                        count=count,
                        no_confirm=no_confirm,
                    )
                )
            else:
                raise e
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    vault_address: ChecksumAddress, count: int | None, indexes: list[int], no_confirm: bool
) -> None:
    setup_logging()
    await setup_clients()
    try:
        await process(
            vault_address=vault_address,
            indexes=indexes,
            count=count,
            no_confirm=no_confirm,
        )
    finally:
        await close_clients()


async def process(
    vault_address: ChecksumAddress, count: int | None, indexes: list[int], no_confirm: bool
) -> None:

    await check_vault_version()
    await check_validators_manager()

    chain_head = await get_chain_justified_head()
    max_activation_epoch = chain_head.epoch - settings.network_config.SHARD_COMMITTEE_PERIOD

    logger.info('Fetching vault validators...')
    vault_contract = VaultContract(vault_address)
    public_keys = await vault_contract.get_registered_validators_public_keys(
        from_block=settings.vault_first_block,
        to_block=chain_head.block_number,
    )
    if indexes:
        active_validators = await _check_exiting_validators(
            indexes=indexes,
            vault_public_keys=public_keys,
            max_activation_epoch=max_activation_epoch,
        )
    else:
        active_validators = await _get_active_validators(
            vault_public_keys=public_keys, max_activation_epoch=max_activation_epoch
        )

    if not active_validators:
        raise click.ClickException('No active validators found')

    if count:
        active_validators = active_validators[:count]
    if not no_confirm:
        click.confirm(
            f'Are you sure you want to exit {len(active_validators)} validators '
            f'with indexes: {', '.join(str(x.index) for x in active_validators)}?',
            abort=True,
        )
    withdrawals = {val.public_key: Gwei(0) for val in active_validators}

    withdrawals_count = len(withdrawals)
    withdrawal_request_fee = await get_withdrawal_request_fee(count=withdrawals_count)
    if withdrawal_request_fee > Web3.to_wei(settings.max_withdrawal_request_fee_gwei, 'gwei'):
        raise click.ClickException(
            'Validator exits are skipped due to high withdrawal fee. '
            f'The current fee is {Web3.from_wei(withdrawal_request_fee, 'gwei')} Gwei. '
            f'You can override the limit with MAX_WITHDRAWAL_REQUEST_FEE_GWEI environment variable.'
        )

    validators_manager_signature = await get_validators_manager_signature(withdrawals)
    tx_hash = await submit_withdraw_validators(
        withdrawals=withdrawals,
        tx_fee=Wei(withdrawal_request_fee * withdrawals_count),
        validators_manager_signature=validators_manager_signature,
    )
    if tx_hash:
        click.secho(
            'Exits for validators with '
            f'index(es) {', '.join(str(val.index) for val in active_validators)} '
            'are successfully initiated',
            bold=True,
            fg='green',
        )


async def _get_active_validators(
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


async def get_validators_manager_signature(withdrawals: dict[HexStr, Gwei]) -> HexStr:
    if not settings.relayer_endpoint:
        return HexStr('0x')
    relayer = RelayerClient()
    # fetch validator manager signature from relayer
    relayer_response = await relayer.withdraw_validators(
        withdrawals=withdrawals,
    )
    if not relayer_response.validators_manager_signature:
        raise click.ClickException('Could not get validator manager signature from relayer')

    return relayer_response.validators_manager_signature
