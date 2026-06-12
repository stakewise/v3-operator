import asyncio
import logging
import sys
from dataclasses import replace
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress
from sw_utils import InterruptHandler
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import close_clients, execution_client, setup_clients
from src.common.contracts import VaultContract
from src.common.execution import (
    check_gas_price,
    check_wallet_balance,
    get_finalized_block_number,
)
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.startup_check import (
    check_execution_nodes_network,
    wait_for_execution_node,
)
from src.common.utils import log_verbose
from src.common.wallet import wallet
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.meta_vault.service import is_meta_vault
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.execution import (
    simulate_redeem_position,
    tx_process_exit_queue,
    tx_redeem_position,
)
from src.redemptions.fetch_positions import (
    cached_fetch_positions_from_ipfs,
    fetch_positions_with_processed_shares,
    update_positions_cache,
    update_processed_shares_cache,
)
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.os_token_converter import (
    OsTokenConverter,
    create_os_token_converter,
)
from src.redemptions.tasks import assign_shares_to_redeem
from src.redemptions.typings import OsTokenPosition
from src.validators.execution import get_withdrawable_assets

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL = 60  # 1 minute
DEFAULT_MIN_QUEUED_ASSETS = Web3.to_wei(0.1, 'ether')
DEFAULT_MIN_QUEUED_ASSETS_GWEI = Web3.from_wei(DEFAULT_MIN_QUEUED_ASSETS, 'gwei')


@click.option(
    '--wallet-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_PASSWORD_FILE',
    help='Absolute path to the wallet password file. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--wallet-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_FILE',
    help='Absolute path to the wallet. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter the comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '--execution-jwt-secret',
    type=str,
    envvar='EXECUTION_JWT_SECRET',
    help='JWT secret key used for signing and verifying JSON Web Tokens'
    ' when connecting to execution nodes.',
)
@click.option(
    '--interval',
    type=int,
    default=DEFAULT_INTERVAL,
    envvar='INTERVAL',
    help='Sleep interval in seconds between processing rounds.',
)
@click.option(
    '--min-queued-assets-gwei',
    type=int,
    default=DEFAULT_MIN_QUEUED_ASSETS_GWEI,
    envvar='MIN_QUEUED_ASSETS_GWEI',
    help='Minimum queued assets (in Gwei) to trigger redemption processing.',
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
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--dry-run',
    help='Simulate redeemOsTokenPositions calls without submitting transactions. '
    'Default is false.',
    envvar='DRY_RUN',
    is_flag=True,
)
@click.option(
    '--network',
    help='The network of the meta vaults.',
    prompt='Enter the network name',
    envvar='NETWORK',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Processes redemptions and exit queue checkpoints.')
# pylint: disable-next=too-many-arguments
def process_redeemer(
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    network: str,
    verbose: bool,
    dry_run: bool,
    log_level: str,
    interval: int,
    min_queued_assets_gwei: int,
    wallet_file: str | None,
    wallet_password_file: str | None,
) -> None:
    settings.set(
        # No specific vault address is set — redemptions are processed across all vaults.
        vault=ZERO_CHECKSUM_ADDRESS,
        vault_dir=Path.home() / '.stakewise',
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        verbose=verbose,
        network=network,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        log_level=log_level,
    )
    try:
        asyncio.run(
            main(
                interval=interval,
                min_queued_assets=Gwei(min_queued_assets_gwei),
                dry_run=dry_run,
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    interval: int,
    min_queued_assets: Gwei,
    dry_run: bool = False,
) -> None:
    setup_logging()
    await setup_clients()
    await _startup_check()
    if dry_run:
        logger.info('Dry run enabled: redeemOsTokenPositions calls will be simulated only.')
    try:
        with InterruptHandler() as interrupt_handler:
            while not interrupt_handler.exit:
                block_number = await execution_client.eth.block_number
                await process(
                    block_number=block_number,
                    min_queued_assets=min_queued_assets,
                    dry_run=dry_run,
                )
                await interrupt_handler.sleep(interval)

    finally:
        await close_clients()


async def process(
    block_number: BlockNumber,
    min_queued_assets: Gwei,
    dry_run: bool = False,
) -> None:
    try:
        await _redeem_os_token_positions(min_queued_assets=min_queued_assets, dry_run=dry_run)
    finally:
        if dry_run:
            logger.info('Dry run: skipping processExitQueue.')
        else:
            # Re-fetch block number after redemption processing
            # to ensure we read the latest on-chain state.
            block_number = await execution_client.eth.block_number
            if await os_token_redeemer_contract.can_process_exit_queue(block_number):
                logger.info('Exit queue can be processed. Calling processExitQueue...')
                await tx_process_exit_queue()


async def _redeem_os_token_positions(
    min_queued_assets: Gwei,
    dry_run: bool = False,
) -> None:
    """Perform the OsToken redemption flow for a single iteration.

    Returns early when there is nothing to redeem; the caller still processes
    the exit queue regardless.
    """
    if not await check_gas_price():
        return

    block_number = await execution_client.eth.block_number

    queued_shares = await os_token_redeemer_contract.queued_shares(block_number)
    os_token_converter = await create_os_token_converter(block_number)
    queued_assets = os_token_converter.to_assets(queued_shares)
    if queued_assets < Web3.to_wei(min_queued_assets, 'gwei'):
        logger.info(
            'Queued assets %s below threshold %s. Skipping to next interval.',
            Web3.from_wei(queued_assets, 'ether'),
            Web3.from_wei(Web3.to_wei(min_queued_assets, 'gwei'), 'ether'),
        )
        return

    nonce = await os_token_redeemer_contract.nonce(block_number)
    if nonce == 0:
        logger.info('Zero nonce for redemption. Skipping to next interval.')
        return

    logger.info(
        'Process queued shares for Redemption: %s (~%s %s)',
        queued_shares,
        Web3.from_wei(queued_assets, 'ether'),
        settings.network_config.VAULT_BALANCE_SYMBOL,
    )

    # Update both caches at the finalized block
    finalized_block_number = await get_finalized_block_number()
    await update_positions_cache(finalized_block_number)
    await update_processed_shares_cache(finalized_block_number)

    # Fetch ALL positions from IPFS so the merkle tree matches the on-chain root.
    all_positions = await cached_fetch_positions_from_ipfs(nonce, block_number)
    if not all_positions:
        logger.info('No positions found. Skipping to next interval.')
        return

    positions_with_processed_shares = await fetch_positions_with_processed_shares(
        nonce=nonce, block_number=block_number
    )
    os_token_positions = await assign_shares_to_redeem(
        positions_with_processed_shares,
        total_redemption_shares=Wei(queued_shares),
    )
    if not os_token_positions:
        logger.info('No redeemable positions found. Skipping to next interval.')
        return

    tree = PositionsMerkleTree(all_positions, nonce)
    await redeem_positions(
        tree=tree,
        os_token_positions=os_token_positions,
        converter=os_token_converter,
        block_number=block_number,
        dry_run=dry_run,
    )


async def redeem_positions(
    tree: PositionsMerkleTree,
    os_token_positions: list[OsTokenPosition],
    converter: OsTokenConverter,
    block_number: BlockNumber,
    dry_run: bool = False,
) -> None:
    """Redeem positions one by one. Each position's shares_to_redeem is already set by
    assign_shares_to_redeem; this function further caps it by the vault's withdrawable assets.

    Meta-vault positions are skipped entirely. Vaults whose on-chain state is
    stale (unharvested) are skipped, since their withdrawable assets would be
    outdated. Aborts the round if a single redemption tx fails.
    """
    vault_to_withdrawable: dict[ChecksumAddress, Wei] = {}
    unharvested_vaults: set[ChecksumAddress] = set()

    for position in os_token_positions:
        shares_to_redeem = position.shares_to_redeem
        assets_to_redeem = converter.to_assets(shares_to_redeem)

        if await is_meta_vault(position.vault):
            logger.warning(
                'Unexpected meta vault position for %s; '
                'redeemable positions should not include meta vaults.',
                position.vault,
            )
            continue

        if position.vault in unharvested_vaults:
            continue

        if position.vault not in vault_to_withdrawable:
            if await VaultContract(position.vault).is_state_update_required(block_number):
                logger.info('Skipping unharvested vault %s', position.vault)
                unharvested_vaults.add(position.vault)
                continue
            vault_to_withdrawable[position.vault] = await get_withdrawable_assets(
                position.vault, harvest_params=None
            )
        withdrawable = vault_to_withdrawable[position.vault]

        if withdrawable < assets_to_redeem:
            shares_to_redeem = converter.to_shares(withdrawable)
            assets_to_redeem = withdrawable

        if shares_to_redeem <= 0:
            continue

        position_to_redeem = replace(position, shares_to_redeem=shares_to_redeem)

        # Always simulate first to catch reverts before broadcasting a real tx.
        if not await simulate_redeem_position(position=position_to_redeem, tree=tree):
            return

        # In dry-run mode we stop at simulation; otherwise submit the real tx.
        if not dry_run:
            if not await tx_redeem_position(position=position_to_redeem, tree=tree):
                return

        vault_to_withdrawable[position.vault] = Wei(withdrawable - assets_to_redeem)


async def _startup_check() -> None:
    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking execution nodes network...')
    await check_execution_nodes_network()

    logger.info('Checking Position Manager role...')
    positions_manager = await os_token_redeemer_contract.positions_manager()
    if positions_manager != wallet.account.address:
        raise RuntimeError(
            f'The Position Manager role must be assigned to the address {wallet.account.address}.'
        )

    logger.info('Checking wallet balance %s...', wallet.address)
    await check_wallet_balance()
