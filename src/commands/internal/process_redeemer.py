import asyncio
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from sw_utils import InterruptHandler
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Wei

from src.common.clients import close_clients, execution_client, setup_clients
from src.common.contracts import (
    VaultContract,
    multicall_contract,
    os_token_redeemer_contract,
)
from src.common.execution import transaction_gas_wrapper
from src.common.harvest import get_harvest_params
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.typings import HarvestParams
from src.common.utils import async_batched, log_verbose
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


@dataclass
class PositionSelectionResult:
    positions_to_redeem: list[OsTokenPosition]
    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None]


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
    wallet_file: str | None,
    wallet_password_file: str | None,
) -> None:
    settings.set(
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
        asyncio.run(main(interval=interval))
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(interval: int = DEFAULT_INTERVAL) -> None:
    setup_logging()
    await setup_clients()
    await _startup_check()
    try:
        with InterruptHandler() as interrupt_handler:
            while not interrupt_handler.exit:
                block_number = await execution_client.eth.block_number
                await process(block_number=block_number)
                await interrupt_handler.sleep(interval)

    finally:
        await close_clients()


async def process(block_number: BlockNumber) -> None:
    await _process_exit_queue(block_number)

    queued_shares = await os_token_redeemer_contract.queued_shares(block_number)
    if queued_shares == 0:
        logger.info('No queued shares for redemption. Skipping to next interval.')
        return

    os_token_converter = await create_os_token_converter(block_number)

    # The contract increments nonce during setRedeemablePositions,
    # but uses nonce - 1 for leaf hash computation during redemption.
    nonce = await os_token_redeemer_contract.nonce(block_number)
    tree_nonce = nonce - 1

    queued_assets = os_token_converter.to_assets(queued_shares)
    logger.info(
        'Queued Shares for Redemption: %s (~%s assets)',
        queued_shares,
        Web3.from_wei(queued_assets, 'ether'),
    )

    redeemable_positions = await _fetch_redeemable_positions(
        tree_nonce=tree_nonce, block_number=block_number
    )

    result = await _select_positions_to_redeem(
        redeemable_positions=redeemable_positions,
        queued_shares=queued_shares,
        os_token_converter=os_token_converter,
        block_number=block_number,
    )

    if not result.positions_to_redeem:
        logger.info('No positions eligible for redemption.')
        return

    tx_hash = await _execute_redemption(
        all_positions=redeemable_positions,
        positions_to_redeem=result.positions_to_redeem,
        vault_to_harvest_params=result.vault_to_harvest_params,
        tree_nonce=tree_nonce,
    )
    if tx_hash:
        logger.info(
            'Successfully redeemed %s OsToken positions. Transaction hash: %s',
            len(result.positions_to_redeem),
            tx_hash,
        )


async def _select_positions_to_redeem(
    redeemable_positions: list[OsTokenPosition],
    queued_shares: int,
    os_token_converter: OsTokenConverter,
    block_number: BlockNumber,
) -> PositionSelectionResult:
    # group positions by vault
    vault_to_positions: defaultdict[ChecksumAddress, list[OsTokenPosition]] = defaultdict(list)
    for position in redeemable_positions:
        vault_to_positions[position.vault].append(position)

    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None] = {}
    vault_to_withdrawable_assets: dict[ChecksumAddress, Wei] = {}

    for vault_address, positions in vault_to_positions.items():
        harvest_params = await get_harvest_params(vault_address, block_number)
        vault_to_harvest_params[vault_address] = harvest_params
        withdrawable_assets = await get_withdrawable_assets(vault_address, harvest_params)

        withdrawable_assets = await _try_redeem_sub_vaults(
            vault_address=vault_address,
            positions=positions,
            withdrawable_assets=withdrawable_assets,
            harvest_params=harvest_params,
            os_token_converter=os_token_converter,
        )
        vault_to_withdrawable_assets[vault_address] = withdrawable_assets

    return _filter_positions_to_redeem(
        vault_to_positions=vault_to_positions,
        vault_to_withdrawable_assets=vault_to_withdrawable_assets,
        vault_to_harvest_params=vault_to_harvest_params,
        queued_shares=queued_shares,
        os_token_converter=os_token_converter,
    )


def _filter_positions_to_redeem(
    vault_to_positions: dict[ChecksumAddress, list[OsTokenPosition]],
    vault_to_withdrawable_assets: dict[ChecksumAddress, Wei],
    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None],
    queued_shares: int,
    os_token_converter: OsTokenConverter,
) -> PositionSelectionResult:
    positions_to_redeem: list[OsTokenPosition] = []
    remaining_shares = queued_shares

    for vault_address, positions in vault_to_positions.items():
        withdrawable_assets = vault_to_withdrawable_assets[vault_address]

        for position in positions:
            if remaining_shares <= 0:
                break

            redeemable_assets = os_token_converter.to_assets(position.available_shares)
            if redeemable_assets > withdrawable_assets:
                continue

            shares_to_redeem = Wei(min(position.available_shares, remaining_shares))
            logger.info(
                'Position Owner: %s, Vault: %s, Shares to Redeem: %s',
                position.owner,
                position.vault,
                shares_to_redeem,
            )
            positions_to_redeem.append(
                OsTokenPosition(
                    vault=position.vault,
                    owner=position.owner,
                    amount=position.amount,
                    available_shares=position.available_shares,
                    shares_to_redeem=shares_to_redeem,
                )
            )
            withdrawable_assets = Wei(withdrawable_assets - redeemable_assets)
            remaining_shares -= shares_to_redeem

        if remaining_shares <= 0:
            break

    return PositionSelectionResult(
        positions_to_redeem=positions_to_redeem,
        vault_to_harvest_params=vault_to_harvest_params,
    )


async def _try_redeem_sub_vaults(
    vault_address: ChecksumAddress,
    positions: list[OsTokenPosition],
    withdrawable_assets: Wei,
    harvest_params: HarvestParams | None,
    os_token_converter: OsTokenConverter,
) -> Wei:
    """If vault is a meta-vault with insufficient assets, redeem from sub-vaults.

    Returns the (possibly updated) withdrawable assets for the vault.
    """
    vault_positions_shares = Wei(sum(p.available_shares for p in positions))
    vault_positions_assets = os_token_converter.to_assets(vault_positions_shares)

    if vault_positions_assets <= withdrawable_assets or not await is_meta_vault(vault_address):
        return withdrawable_assets

    logger.info('Vault %s is a meta-vault with insufficient withdrawable assets.', vault_address)
    additional_assets_needed = Wei(vault_positions_assets - withdrawable_assets)
    try:
        tx_hash = await os_token_redeemer_contract.redeem_sub_vaults_assets(
            vault_address, additional_assets_needed
        )
        logger.info(
            'redeemSubVaultsAssets confirmed for vault %s. Tx Hash: %s',
            vault_address,
            tx_hash,
        )
    except RuntimeError:
        logger.error(
            'redeemSubVaultsAssets failed for vault %s. '
            'Proceeding with current withdrawable assets.',
            vault_address,
        )
        return withdrawable_assets

    # Re-query actual withdrawable assets on-chain after sub-vault redemption
    # to avoid TOCTOU issues with stale values
    return await get_withdrawable_assets(vault_address, harvest_params)


async def _execute_redemption(
    all_positions: list[OsTokenPosition],
    positions_to_redeem: list[OsTokenPosition],
    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None],
    tree_nonce: int,
) -> HexStr | None:
    multiproof = _get_multi_proof(
        all_positions=all_positions,
        positions_to_redeem=positions_to_redeem,
        tree_nonce=tree_nonce,
    )
    calls: list[tuple[ChecksumAddress, HexStr]] = []

    for vault in set(pos.vault for pos in positions_to_redeem):
        harvest_params = vault_to_harvest_params.get(vault)
        if harvest_params:
            vault_contract = VaultContract(vault)
            calls.append(
                (
                    vault_contract.contract_address,
                    vault_contract.get_update_state_call(harvest_params),
                )
            )

    # Maps to Solidity struct:
    # OsTokenPosition(address vault, address owner, uint256 leafShares, uint256 sharesToRedeem)
    positions_arg = [
        (pos.vault, pos.owner, pos.amount, pos.shares_to_redeem) for pos in positions_to_redeem
    ]
    redeem_call = os_token_redeemer_contract.encode_abi(
        fn_name='redeemOsTokenPositions',
        args=[positions_arg, multiproof.proof, multiproof.proof_flags],
    )
    calls.append((os_token_redeemer_contract.contract_address, redeem_call))

    try:
        tx_function = multicall_contract.functions.aggregate(calls)
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


async def _fetch_redeemable_positions(
    tree_nonce: int, block_number: BlockNumber
) -> list[OsTokenPosition]:
    positions: list[OsTokenPosition] = []
    async for batch in async_batched(
        iter_os_token_positions(block_number=block_number), batch_size
    ):
        processed_shares_batch = await get_processed_shares_batch(
            os_token_positions_batch=batch,
            nonce=tree_nonce,
            block_number=block_number,
        )
        for position, processed_shares in zip(batch, processed_shares_batch):
            available_shares = position.amount - processed_shares
            if available_shares <= 0:
                continue
            positions.append(
                OsTokenPosition(
                    owner=position.owner,
                    vault=position.vault,
                    amount=position.amount,
                    available_shares=Wei(available_shares),
                )
            )

    return positions


async def _process_exit_queue(block_number: BlockNumber) -> None:
    """
    Call processExitQueue() on the redeemer contract if canProcessExitQueue
    to create a new checkpoint that converts accumulated redeemed/swapped
    shares into claimable assets for users in the exit queue.
    """
    can_process_exit_queue = await os_token_redeemer_contract.can_process_exit_queue(block_number)
    if can_process_exit_queue:
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


def _get_multi_proof(
    tree_nonce: int,
    all_positions: list[OsTokenPosition],
    positions_to_redeem: list[OsTokenPosition],
) -> MultiProof[tuple[bytes, int]]:
    all_leaves = [p.merkle_leaf(tree_nonce) for p in all_positions]
    tree = StandardMerkleTree.of(
        all_leaves,
        ['uint256', 'address', 'uint256', 'address'],
    )
    redeem_leaves = [p.merkle_leaf(tree_nonce) for p in positions_to_redeem]
    return tree.get_multi_proof(redeem_leaves)
