import asyncio
import logging
import sys
from collections import defaultdict
from dataclasses import replace
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from sw_utils import InterruptHandler
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Gwei, Wei

from src.common.clients import close_clients, execution_client, setup_clients
from src.common.contracts import os_token_redeemer_contract
from src.common.execution import transaction_gas_wrapper
from src.common.harvest import get_multiple_harvest_params
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.typings import HarvestParams
from src.common.utils import log_verbose
from src.common.wallet import wallet
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.meta_vault.service import is_meta_vault
from src.redemptions.os_token_converter import (
    OsTokenConverter,
    create_os_token_converter,
)
from src.redemptions.tasks import (
    batch_size,
    get_processed_shares_batch,
    iter_os_token_positions,
)
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
    '--network',
    help='The network of the meta vaults.',
    prompt='Enter the network name',
    envvar='NETWORK',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(
    help='Monitors the EthOsTokenRedeemer/GnoOsTokenRedeemer contracts'
    ' and automatically processes OsToken position redemptions'
    ' and exit queue checkpoints.'
)
# pylint: disable-next=too-many-arguments
def process_redeemer(
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    network: str,
    verbose: bool,
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
        asyncio.run(main(interval=interval, min_queued_assets=Gwei(min_queued_assets_gwei)))
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    interval: int,
    min_queued_assets: Gwei,
) -> None:
    setup_logging()
    await setup_clients()
    await _startup_check()
    try:
        with InterruptHandler() as interrupt_handler:
            while not interrupt_handler.exit:
                block_number = await execution_client.eth.block_number
                await process(block_number=block_number, min_queued_assets=min_queued_assets)
                await interrupt_handler.sleep(interval)

    finally:
        await close_clients()


async def process(
    block_number: BlockNumber,
    min_queued_assets: Gwei,
) -> None:
    # Step 1: Process exit queue
    await _process_exit_queue(block_number)

    # Re-fetch block number after exit queue processing
    # to ensure we read the latest on-chain state
    block_number = await execution_client.eth.block_number

    # Step 2: Check queued shares
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

    # The Merkle root was calculated before the nonce was incremented
    # in setRedeemablePositions, so we use the previous nonce for Merkle proofs.
    nonce = await os_token_redeemer_contract.nonce(block_number)
    if nonce == 0:
        logger.info('Zero nonce for redemption. Skipping to next interval.')
        return
    prev_nonce = nonce - 1

    logger.info(
        'Process queued shares for Redemption: %s (~%s %s)',
        queued_shares,
        Web3.from_wei(queued_assets, 'ether'),
        settings.network_config.VAULT_BALANCE_SYMBOL,
    )
    # Step 3: Fetch ALL positions from IPFS (needed for correct merkle tree)
    all_positions = await fetch_positions_from_ipfs(block_number)
    if not all_positions:
        logger.info('No positions found. Skipping to next interval.')
        return

    # Step 4: Calculate redeemable shares
    os_token_positions = await calculate_redeemable_shares(all_positions, prev_nonce, block_number)
    if not os_token_positions:
        logger.info('No redeemable positions found. Skipping to next interval.')
        return

    # Step 5: Fetch vault params
    vaults = {p.vault for p in os_token_positions}
    vault_to_harvest_params = await get_multiple_harvest_params(list(vaults), block_number)
    vault_to_withdrawable_assets: dict[ChecksumAddress, Wei] = {}
    for vault in vaults:
        vault_to_withdrawable_assets[vault] = await get_withdrawable_assets(
            vault, vault_to_harvest_params.get(vault)
        )

    # Step 6: Select positions
    positions_to_redeem = await select_positions(
        os_token_positions=os_token_positions,
        queued_shares=queued_shares,
        converter=os_token_converter,
        vault_to_harvest_params=vault_to_harvest_params,
        vault_to_withdrawable_assets=vault_to_withdrawable_assets,
    )

    if not positions_to_redeem:
        logger.info('No positions eligible for redemption.')
        return

    # Step 7: Execute redemption (uses all_positions for complete merkle tree)
    tx_hash = await execute_redemption(
        all_positions=all_positions,
        positions_to_redeem=positions_to_redeem,
        vault_to_harvest_params=vault_to_harvest_params,
        nonce=prev_nonce,
    )
    if tx_hash:
        logger.info(
            'Successfully redeemed %s OsToken positions. Transaction hash: %s',
            len(positions_to_redeem),
            tx_hash,
        )


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


async def fetch_positions_from_ipfs(block_number: BlockNumber) -> list[OsTokenPosition]:
    positions: list[OsTokenPosition] = []
    async for position in iter_os_token_positions(block_number=block_number):
        positions.append(position)
    return positions


async def calculate_redeemable_shares(
    all_positions: list[OsTokenPosition],
    nonce: int,
    block_number: BlockNumber,
) -> list[OsTokenPosition]:
    """Query processed shares and return positions with available_shares > 0."""
    redeemable: list[OsTokenPosition] = []

    for i in range(0, len(all_positions), batch_size):
        batch = all_positions[i : i + batch_size]
        processed_shares_batch = await get_processed_shares_batch(
            os_token_positions_batch=batch,
            nonce=nonce,
            block_number=block_number,
        )
        for position, processed_shares in zip(batch, processed_shares_batch):
            available_shares = position.leaf_shares - processed_shares
            if available_shares <= 0:
                continue
            redeemable.append(
                OsTokenPosition(
                    owner=position.owner,
                    vault=position.vault,
                    leaf_shares=position.leaf_shares,
                    available_shares=Wei(available_shares),
                )
            )

    return redeemable


async def select_positions(
    os_token_positions: list[OsTokenPosition],
    queued_shares: int,
    converter: OsTokenConverter,
    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None],
    vault_to_withdrawable_assets: dict[ChecksumAddress, Wei],
) -> list[OsTokenPosition]:
    """Select positions to redeem in IPFS order, capped by queued shares and withdrawable assets.

    Pre-computes meta-vault redemptions for all vaults, then iterates positions
    in their original IPFS ordering.
    """
    vault_to_withdrawable_assets = await _redeem_meta_vaults(
        os_token_positions=os_token_positions,
        queued_shares=queued_shares,
        converter=converter,
        vault_to_harvest_params=vault_to_harvest_params,
        vault_to_withdrawable_assets=vault_to_withdrawable_assets,
    )

    positions_to_redeem: list[OsTokenPosition] = []
    remaining_shares = queued_shares

    for position in os_token_positions:
        if remaining_shares <= 0:
            break

        withdrawable_assets = vault_to_withdrawable_assets.get(position.vault, Wei(0))
        shares_to_redeem = Wei(min(position.available_shares, remaining_shares))
        redeemable_assets = converter.to_assets(shares_to_redeem)

        if redeemable_assets > withdrawable_assets:
            shares_to_redeem = converter.to_shares(withdrawable_assets)
            if shares_to_redeem <= 0:
                continue
            redeemable_assets = withdrawable_assets

        logger.info(
            'Position Owner: %s, Vault: %s, Shares to Redeem: %s',
            position.owner,
            position.vault,
            shares_to_redeem,
        )
        positions_to_redeem.append(replace(position, shares_to_redeem=shares_to_redeem))
        vault_to_withdrawable_assets[position.vault] = Wei(withdrawable_assets - redeemable_assets)
        remaining_shares -= shares_to_redeem

    return positions_to_redeem


async def _redeem_meta_vaults(
    os_token_positions: list[OsTokenPosition],
    queued_shares: int,
    converter: OsTokenConverter,
    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None],
    vault_to_withdrawable_assets: dict[ChecksumAddress, Wei],
) -> dict[ChecksumAddress, Wei]:
    """Pre-compute meta-vault redemptions for all vaults that need them.

    Estimates per-vault asset needs from positions (in IPFS order, capped by queued shares),
    then attempts meta-vault redemption for any vault with a deficit.
    Returns updated vault-to-withdrawable mapping.
    """
    vault_to_withdrawable = dict(vault_to_withdrawable_assets)
    vault_to_needed: defaultdict[ChecksumAddress, Wei] = defaultdict(lambda: Wei(0))
    remaining = queued_shares

    for pos in os_token_positions:
        if remaining <= 0:
            break
        shares = Wei(min(pos.available_shares, remaining))
        vault_to_needed[pos.vault] = Wei(vault_to_needed[pos.vault] + converter.to_assets(shares))
        remaining -= shares

    for vault, needed in vault_to_needed.items():
        withdrawable = vault_to_withdrawable.get(vault, Wei(0))
        if needed > withdrawable:
            vault_to_withdrawable[vault] = await _try_redeem_meta_vault(
                vault,
                Wei(needed - withdrawable),
                withdrawable,
                vault_to_harvest_params.get(vault),
            )

    return vault_to_withdrawable


async def _try_redeem_meta_vault(
    vault_address: ChecksumAddress,
    deficit: Wei,
    current_withdrawable: Wei,
    harvest_params: HarvestParams | None,
) -> Wei:
    """If vault is a meta-vault, redeem sub-vaults for the deficit.

    Returns the (possibly updated) withdrawable assets.
    """
    if not await is_meta_vault(vault_address):
        return current_withdrawable

    logger.info('Vault %s is a meta-vault with insufficient withdrawable assets.', vault_address)
    try:
        tx_hash = await os_token_redeemer_contract.redeem_sub_vaults_assets(vault_address, deficit)
        logger.info(
            'redeemSubVaultsAssets confirmed for vault %s. Tx Hash: %s',
            vault_address,
            tx_hash,
        )
    except (Web3Exception, RuntimeError):
        logger.error(
            'redeemSubVaultsAssets failed for vault %s. '
            'Proceeding with current withdrawable assets.',
            vault_address,
        )
        return current_withdrawable

    # Re-query actual withdrawable assets on-chain after sub-vault redemption
    return await get_withdrawable_assets(vault_address, harvest_params)


async def execute_redemption(
    all_positions: list[OsTokenPosition],
    positions_to_redeem: list[OsTokenPosition],
    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None],
    nonce: int,
) -> HexStr | None:
    """Build multiproof from all positions and execute the redemption transaction."""
    multiproof = build_multi_proof(
        all_positions=all_positions,
        positions_to_redeem=positions_to_redeem,
        tree_nonce=nonce,
    )
    calls: list[HexStr] = []

    for vault in set(pos.vault for pos in positions_to_redeem):
        harvest_params = vault_to_harvest_params.get(vault)
        if harvest_params:
            calls.append(
                os_token_redeemer_contract.encode_abi(
                    fn_name='updateVaultState',
                    args=[
                        vault,
                        (
                            harvest_params.rewards_root,
                            harvest_params.reward,
                            harvest_params.unlocked_mev_reward,
                            harvest_params.proof,
                        ),
                    ],
                )
            )

    # Maps to Solidity struct:
    # OsTokenPosition(address vault, address owner, uint256 leafShares, uint256 sharesToRedeem)
    positions_arg = [
        (pos.vault, pos.owner, pos.leaf_shares, pos.shares_to_redeem) for pos in positions_to_redeem
    ]
    calls.append(
        os_token_redeemer_contract.encode_abi(
            fn_name='redeemOsTokenPositions',
            args=[positions_arg, multiproof.proof, multiproof.proof_flags],
        )
    )

    try:
        tx_function = os_token_redeemer_contract.functions.multicall(calls)
        tx = await transaction_gas_wrapper(tx_function=tx_function)
    except Web3Exception:
        logger.exception('Failed to redeem os token positions')
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Failed to redeem os token positions...')
        return None

    return tx_hash


async def _startup_check() -> None:
    positions_manager = await os_token_redeemer_contract.positions_manager()
    if positions_manager != wallet.account.address:
        raise RuntimeError(
            f'The Position Manager role must be assigned to the address {wallet.account.address}.'
        )


def build_multi_proof(
    tree_nonce: int,
    all_positions: list[OsTokenPosition],
    positions_to_redeem: list[OsTokenPosition],
) -> MultiProof[tuple[int, ChecksumAddress, Wei, ChecksumAddress]]:
    """Build a merkle multiproof from all positions, proving the positions to redeem."""
    all_leaves = [p.merkle_leaf(tree_nonce) for p in all_positions]
    tree = StandardMerkleTree.of(
        all_leaves,
        ['uint256', 'address', 'uint256', 'address'],
    )
    redeem_leaves = [p.merkle_leaf(tree_nonce) for p in positions_to_redeem]
    return tree.get_multi_proof(redeem_leaves)
