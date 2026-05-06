import asyncio
import logging
import sys
from dataclasses import replace
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from hexbytes import HexBytes
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from sw_utils import InterruptHandler
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Gwei, Wei

from src.common.clients import close_clients, execution_client, setup_clients
from src.common.contracts import (
    MetaVaultContract,
    SubVaultsRegistryContract,
    VaultContract,
    multicall_contract,
    os_token_redeemer_contract,
)
from src.common.execution import (
    check_gas_price,
    transaction_gas_wrapper,
    wait_for_execution_endpoints_synced,
)
from src.common.harvest import get_multiple_harvest_params
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.common.wallet import wallet
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.meta_vault.graph import graph_get_vaults
from src.meta_vault.service import is_meta_vault, is_meta_vault_state_update_required
from src.meta_vault.tasks import process_meta_vault_tree
from src.meta_vault.typings import SubVaultRedemption
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
    '--graph-endpoint',
    type=str,
    envvar='GRAPH_ENDPOINT',
    # default is endpoint from network config
    help='API endpoint for graph node.',
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
    graph_endpoint: str | None,
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
        graph_endpoint=graph_endpoint,
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
            )
        )
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
                await process(
                    block_number=block_number,
                    min_queued_assets=min_queued_assets,
                )
                await interrupt_handler.sleep(interval)

    finally:
        await close_clients()


async def process(
    block_number: BlockNumber,
    min_queued_assets: Gwei,
) -> None:
    try:
        await _redeem_os_token_positions(min_queued_assets=min_queued_assets)
    finally:
        # Re-fetch block number after redemption processing
        # to ensure we read the latest on-chain state.
        block_number = await execution_client.eth.block_number
        await _process_exit_queue(block_number)


async def _redeem_os_token_positions(
    min_queued_assets: Gwei,
) -> None:
    """Perform the OsToken redemption flow for a single iteration.

    Returns early without raising when there is nothing to redeem; the caller
    is responsible for processing the exit queue regardless of the outcome.
    """
    if not await check_gas_price():
        return

    # Re-fetch block number after exit queue processing
    # to ensure we read the latest on-chain state
    block_number = await execution_client.eth.block_number

    # Check queued shares
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

    # Fetch ALL positions from IPFS (needed for correct merkle tree)
    all_positions = await fetch_positions_from_ipfs(block_number)
    if not all_positions:
        logger.info('No positions found. Skipping to next interval.')
        return

    # Calculate redeemable shares
    os_token_positions = await calculate_redeemable_shares(all_positions, prev_nonce, block_number)
    if not os_token_positions:
        logger.info('No redeemable positions found. Skipping to next interval.')
        return

    # Bring every involved vault up to date on-chain so subsequent reads
    # and redemption transactions run against fresh state — no harvest_params
    # plumbing and no updateVaultState bundled in a multicall.
    vaults = list({position.vault for position in os_token_positions})
    await update_vaults_state(vaults=vaults, block_number=block_number)

    # Redeem each position end-to-end in a single loop. Withdrawable assets
    # are fetched once per vault and cached; meta vaults short on assets trigger
    # sub-vault redemption inline; one redeemOsTokenPositions tx is submitted per
    # position.
    await redeem_positions(
        all_positions=all_positions,
        os_token_positions=os_token_positions,
        queued_shares=queued_shares,
        converter=os_token_converter,
        tree_nonce=prev_nonce,
    )


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
            unprocessed_shares = position.leaf_shares - processed_shares
            if unprocessed_shares <= 0:
                continue
            redeemable.append(
                OsTokenPosition(
                    owner=position.owner,
                    vault=position.vault,
                    leaf_shares=position.leaf_shares,
                    unprocessed_shares=Wei(unprocessed_shares),
                )
            )

    return redeemable


async def update_vaults_state(
    vaults: list[ChecksumAddress],
    block_number: BlockNumber,
) -> None:
    """Bring every vault in ``vaults`` up to date on-chain.

    Meta vaults that need a state update are harvested via process_meta_vault_tree.
    Regular vaults with pending updates are batched into a single multicall
    submitting ``updateState`` for each. After this call, ``get_withdrawable_assets``
    reflects fresh state, so subsequent redemption decisions can be made without
    threading harvest_params through every read.
    """
    regular_vaults: list[ChecksumAddress] = []
    meta_vaults_map = await graph_get_vaults(
        is_meta_vault=True,
    )
    for vault in vaults:
        if await is_meta_vault(vault):
            if await is_meta_vault_state_update_required(vault):
                try:
                    await process_meta_vault_tree(vault=vault, meta_vaults_map=meta_vaults_map)
                except Exception as e:
                    raise RuntimeError(
                        f'Failed to process meta vault tree for vault {vault}'
                    ) from e

        else:
            regular_vaults.append(vault)

    if not regular_vaults:
        return

    vault_to_harvest_params = await get_multiple_harvest_params(regular_vaults, block_number)
    calls: list[tuple[ChecksumAddress, HexStr]] = []
    for vault in regular_vaults:
        harvest_params = vault_to_harvest_params.get(vault)
        if harvest_params is None:
            continue
        vault_contract = VaultContract(vault)
        calls.append(
            (vault_contract.contract_address, vault_contract.get_update_state_call(harvest_params))
        )

    if not calls:
        return

    tx_hash = await multicall_contract.tx_aggregate(calls)
    logger.info('Waiting for Update State multicall tx %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        HexBytes(Web3.to_bytes(hexstr=tx_hash)), timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        raise RuntimeError(f'Update State multicall tx failed. Tx Hash: {tx_hash}')
    logger.info('Update State multicall confirmed. Tx Hash: %s', tx_hash)


async def redeem_positions(
    all_positions: list[OsTokenPosition],
    os_token_positions: list[OsTokenPosition],
    queued_shares: int,
    converter: OsTokenConverter,
    tree_nonce: int,
) -> None:
    """Walk redeemable positions in IPFS order and redeem each one in turn.

    Per position:
    - Fetch the vault's withdrawable assets (cached per vault and decremented
      after each successful redemption).
    - For meta vaults short on withdrawable, redeem sub-vaults and refetch.
    - Cap shares by both remaining queued shares and withdrawable assets.
    - Submit a redeemOsTokenPositions transaction for the single position.

    Stops once queued shares are exhausted, or aborts the round if a single
    position's redemption transaction fails.
    """
    remaining_shares = queued_shares
    vault_to_withdrawable: dict[ChecksumAddress, Wei] = {}

    for position in os_token_positions:
        if remaining_shares <= 0:
            break

        shares_to_redeem = Wei(min(position.unprocessed_shares, remaining_shares))
        assets_to_redeem = converter.to_assets(shares_to_redeem)

        if position.vault not in vault_to_withdrawable:
            vault_to_withdrawable[position.vault] = await get_withdrawable_assets(
                position.vault, harvest_params=None
            )
        withdrawable = vault_to_withdrawable[position.vault]

        if withdrawable < assets_to_redeem and await is_meta_vault(position.vault):
            last_receipt_block = await _redeem_meta_vault_sub_vaults(
                vault_address=position.vault, assets=assets_to_redeem
            )
            if last_receipt_block is not None:
                await wait_for_execution_endpoints_synced(last_receipt_block)
            withdrawable = await get_withdrawable_assets(position.vault, harvest_params=None)
            vault_to_withdrawable[position.vault] = withdrawable

        if withdrawable < assets_to_redeem:
            shares_to_redeem = converter.to_shares(withdrawable)
            assets_to_redeem = withdrawable

        if shares_to_redeem <= 0:
            continue

        position_to_redeem = replace(position, shares_to_redeem=shares_to_redeem)
        receipt_block = await _submit_redeem_position(
            position=position_to_redeem,
            all_positions=all_positions,
            tree_nonce=tree_nonce,
        )
        if receipt_block is None:
            return

        await wait_for_execution_endpoints_synced(receipt_block)

        vault_to_withdrawable[position.vault] = Wei(withdrawable - assets_to_redeem)
        remaining_shares -= shares_to_redeem


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


async def _redeem_meta_vault_sub_vaults(
    vault_address: ChecksumAddress,
    assets: Wei,
) -> BlockNumber | None:
    """Redeem from sub-vaults to bring a meta vault's withdrawable assets up to ``assets``.

    Builds a bottom-up redeem order so deepest nested meta vaults are redeemed first,
    then submits one redeemSubVaultsAssets transaction per entry. Failures abort the
    sequence; the caller refetches withdrawable to discover whatever progress was made.

    Returns the block number of the last successful redeemSubVaultsAssets receipt, or
    ``None`` if no transaction succeeded. The caller uses this as a sync barrier so
    subsequent withdrawable reads cannot land on a fallback endpoint that has not
    yet seen the redemptions.
    """
    try:
        redeem_order = await _build_meta_vault_redeem_order(vault_address, assets)
    except Exception:
        logger.exception(
            'Failed to build meta-vault redeem order for vault %s. '
            'Proceeding with current withdrawable assets.',
            vault_address,
        )
        return None

    last_receipt_block: BlockNumber | None = None
    for redeem_entry in redeem_order:
        try:
            tx_hash, receipt_block = await os_token_redeemer_contract.redeem_sub_vaults_assets(
                redeem_entry.vault, redeem_entry.assets
            )
            logger.info(
                'redeemSubVaultsAssets confirmed for vault %s. Tx Hash: %s',
                redeem_entry.vault,
                tx_hash,
            )
            last_receipt_block = receipt_block
        except (Web3Exception, RuntimeError, ValueError):
            logger.exception(
                'redeemSubVaultsAssets failed for vault %s. '
                'Proceeding with current withdrawable assets.',
                redeem_entry.vault,
            )
            return last_receipt_block

    return last_receipt_block


async def _build_meta_vault_redeem_order(
    vault: ChecksumAddress,
    assets: Wei,
) -> list[SubVaultRedemption]:
    """Build bottom-up order of meta vault redemptions for nested meta vaults.

    For MetaVault A with sub-vault B (also a meta vault) with sub-vaults C, D:
    returns [(B, assets_B), (A, assets_A)] so B is redeemed first.
    """
    order: list[SubVaultRedemption] = []

    meta_vault_contract = MetaVaultContract(vault)
    registry_address = await meta_vault_contract.sub_vaults_registry()
    registry = SubVaultsRegistryContract(registry_address)

    redemptions = await registry.calculate_sub_vaults_redemptions(assets)

    for redemption in redemptions:
        if redemption.assets > 0 and await is_meta_vault(redemption.vault):
            nested_order = await _build_meta_vault_redeem_order(redemption.vault, redemption.assets)
            order.extend(nested_order)

    order.append(SubVaultRedemption(vault=vault, assets=assets))
    return order


async def _submit_redeem_position(
    position: OsTokenPosition,
    all_positions: list[OsTokenPosition],
    tree_nonce: int,
) -> BlockNumber | None:
    """Submit one redeemOsTokenPositions transaction for a single position.

    Returns the receipt's block number on a confirmed successful transaction,
    ``None`` otherwise. The caller uses the returned block as a sync barrier so
    that subsequent reads (e.g. withdrawable balances for the next position)
    cannot land on a fallback endpoint that has not yet seen the redemption.
    """
    multiproof = _build_multi_proof(
        tree_nonce=tree_nonce,
        all_positions=all_positions,
        positions_to_redeem=[position],
    )
    positions_arg = [
        (position.vault, position.owner, position.leaf_shares, position.shares_to_redeem)
    ]
    try:
        tx_function = os_token_redeemer_contract.contract.functions.redeemOsTokenPositions(
            positions_arg, multiproof.proof, multiproof.proof_flags
        )
        tx = await transaction_gas_wrapper(tx_function=tx_function)
    except (Web3Exception, RuntimeError, ValueError):
        logger.exception(
            'Failed to redeem position (vault %s, owner %s)',
            position.vault,
            position.owner,
        )
        return None

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
        return None

    logger.info(
        'Redeemed %s shares for position (vault %s, owner %s). Tx Hash: %s',
        position.shares_to_redeem,
        position.vault,
        position.owner,
        tx_hash,
    )
    return tx_receipt['blockNumber']


def _build_multi_proof(
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
