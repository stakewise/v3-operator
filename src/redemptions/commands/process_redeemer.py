import asyncio
import logging
import sys
from dataclasses import replace
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from sw_utils import InterruptHandler
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Gwei, Wei

from src.common.clients import close_clients, execution_client, setup_clients
from src.common.contracts import VaultContract
from src.common.execution import (
    check_gas_price,
    get_finalized_block_number,
    transaction_gas_wrapper,
    wait_for_execution_endpoints_synced,
)
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.common.wallet import wallet
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.meta_vault.service import is_meta_vault
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.fetch_positions import (
    cached_fetch_positions_from_ipfs,
    fetch_positions_with_processed_shares,
    update_positions_cache,
    update_processed_shares_cache,
)
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
            await _process_exit_queue(block_number)


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

    await redeem_positions(
        all_positions=all_positions,
        os_token_positions=os_token_positions,
        converter=os_token_converter,
        nonce=nonce,
        block_number=block_number,
        dry_run=dry_run,
    )


# pylint: disable-next=too-many-arguments
async def redeem_positions(
    all_positions: list[OsTokenPosition],
    os_token_positions: list[OsTokenPosition],
    converter: OsTokenConverter,
    nonce: int,
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
        redeemed = await _submit_redeem_position(
            position=position_to_redeem,
            all_positions=all_positions,
            nonce=nonce,
            dry_run=dry_run,
        )
        if not redeemed:
            return

        vault_to_withdrawable[position.vault] = Wei(withdrawable - assets_to_redeem)


async def _process_exit_queue(block_number: BlockNumber) -> None:
    """Call processExitQueue() on the redeemer contract if canProcessExitQueue."""
    can_process_exit_queue = await os_token_redeemer_contract.can_process_exit_queue(block_number)
    if not can_process_exit_queue:
        return
    logger.info('Exit queue can be processed. Calling processExitQueue...')
    tx_hash = await os_token_redeemer_contract.process_exit_queue()
    logger.info('Waiting for processExitQueue transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx_hash, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('processExitQueue transaction failed. Tx Hash: %s', tx_hash)
    else:
        logger.info('processExitQueue confirmed. Tx Hash: %s', tx_hash)


async def _startup_check() -> None:
    positions_manager = await os_token_redeemer_contract.positions_manager()
    if positions_manager != wallet.account.address:
        raise RuntimeError(
            f'The Position Manager role must be assigned to the address {wallet.account.address}.'
        )


async def _submit_redeem_position(
    position: OsTokenPosition,
    all_positions: list[OsTokenPosition],
    nonce: int,
    dry_run: bool = False,
) -> bool:
    """Submit one redeemOsTokenPositions transaction for a single position.

    Returns ``True`` on success, ``False`` otherwise. When ``dry_run`` is set,
    the call is simulated via ``.call()`` instead of being submitted.
    """
    multiproof = _build_multi_proof(
        nonce=nonce,
        all_positions=all_positions,
        positions_to_redeem=[position],
    )
    positions_arg = [
        (position.vault, position.owner, position.leaf_shares, position.shares_to_redeem)
    ]
    tx_function = os_token_redeemer_contract.contract.functions.redeemOsTokenPositions(
        positions_arg, multiproof.proof, multiproof.proof_flags
    )

    if dry_run:
        try:
            await tx_function.call()
        except (Web3Exception, RuntimeError, ValueError) as e:
            logger.error(
                'Dry run: failed to simulate redeem position (vault %s, owner %s): %r',
                position.vault,
                position.owner,
                e,
            )
            return False
        logger.info(
            'Dry run: simulated redeeming %s shares for position (vault %s, owner %s) successfully',
            position.shares_to_redeem,
            position.vault,
            position.owner,
        )
        return True

    try:
        tx = await transaction_gas_wrapper(tx_function=tx_function)
    except (Web3Exception, RuntimeError, ValueError):
        logger.exception(
            'Failed to redeem position (vault %s, owner %s)',
            position.vault,
            position.owner,
        )
        return False

    tx_hash = Web3.to_hex(tx)
    logger.info(
        'Waiting for redeemOsTokenPositions tx %s (vault %s, owner %s) confirmation',
        tx_hash,
        position.vault,
        position.owner,
    )
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error(
            'Failed to redeem position (vault %s, owner %s). Tx Hash: %s',
            position.vault,
            position.owner,
            tx_hash,
        )
        return False

    logger.info(
        'Redeemed %s shares for position (vault %s, owner %s). Tx Hash: %s',
        position.shares_to_redeem,
        position.vault,
        position.owner,
        tx_hash,
    )
    # Barrier against fallback endpoints lagging behind the receipt block.
    await wait_for_execution_endpoints_synced(tx_receipt['blockNumber'])
    return True


def _build_multi_proof(
    nonce: int,
    all_positions: list[OsTokenPosition],
    positions_to_redeem: list[OsTokenPosition],
) -> MultiProof[tuple[int, ChecksumAddress, Wei, ChecksumAddress]]:
    """Build a merkle multiproof from all positions, proving the positions to redeem."""
    all_leaves = [p.merkle_leaf(nonce - 1) for p in all_positions]
    tree = StandardMerkleTree.of(
        all_leaves,
        ['uint256', 'address', 'uint256', 'address'],
    )
    redeem_leaves = [p.merkle_leaf(nonce - 1) for p in positions_to_redeem]
    return tree.get_multi_proof(redeem_leaves)
