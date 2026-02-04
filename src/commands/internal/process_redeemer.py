import asyncio
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import cast

import click
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from sw_utils import InterruptHandler
from web3 import Web3
from web3.types import Wei

from src.common.clients import (
    close_clients,
    execution_client,
    ipfs_fetch_client,
    setup_clients,
)
from src.common.contracts import (
    VaultContract,
    multicall_contract,
    os_token_redeemer_contract,
)
from src.common.execution import transaction_gas_wrapper
from src.common.harvest import get_harvest_params
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.typings import HarvestParams
from src.common.utils import log_verbose
from src.common.wallet import wallet
from src.config.networks import AVAILABLE_NETWORKS, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings
from src.meta_vault.service import is_meta_vault
from src.redemptions.os_token_converter import create_os_token_converter
from src.redemptions.typings import RedeemablePosition
from src.validators.execution import get_withdrawable_assets

logger = logging.getLogger(__name__)

SLEEP_INTERVAL = 60  # 1 minute


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
    help='API endpoint for graph node.',
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
    graph_endpoint: str,
    network: str,
    verbose: bool,
    log_level: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
) -> None:
    settings.set(
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
        asyncio.run(main())
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


# pylint: disable-next=too-many-locals
async def main() -> None:
    """
    Monitors the EthOsTokenRedeemer/GnoOsTokenRedeemer contracts
    and automatically processes OsToken position redemptions
    and exit queue checkpoints.
    """
    setup_logging()
    await setup_clients()
    await _startup_check()
    try:
        with InterruptHandler() as interrupt_handler:
            while not interrupt_handler.exit:
                block_number = await execution_client.eth.block_number
                await process(
                    block_number=block_number,
                )
                await interrupt_handler.sleep(SLEEP_INTERVAL)

    finally:
        await close_clients()


# pylint: disable-next=too-many-locals
async def process(block_number: BlockNumber) -> None:
    """
    Monitors the EthOsTokenRedeemer/GnoOsTokenRedeemer contracts
    and automatically processes OsToken position redemptions
    and exit queue checkpoints.
    """
    # Check Exit Queue Processing
    await _process_exit_queue(block_number)

    # Check Queued Shares for Redemption
    queued_shares = await os_token_redeemer_contract.queued_shares(block_number)
    if queued_shares == 0:
        logger.info('No queued shares for redemption. Skipping to next interval.')
        return

    os_token_converter = await create_os_token_converter(block_number)
    nonce = await os_token_redeemer_contract.nonce(block_number)

    queued_assets = os_token_converter.to_assets(queued_shares)
    logger.info(
        'Queued Shares for Redemption: %s(~%s assets)',
        queued_shares,
        Web3.from_wei(queued_assets, 'ether'),
    )

    # Fetch Positions from IPFS
    redeemable_positions_meta = await os_token_redeemer_contract.redeemable_positions(block_number)
    redeemable_positions = await fetch_redeemable_positions(redeemable_positions_meta.ipfs_hash)

    # Calculate Redeemable Shares Per Position
    for redeemable_position in redeemable_positions:
        # Compute leaf hash
        leaf_hash = redeemable_position.merkle_leaf_bytes(nonce - 1)
        # Get already processed shares
        leaf_processed_shares = await os_token_redeemer_contract.leaf_to_processed_shares(
            leaf_hash, block_number
        )
        # Calculate redeemable shares
        redeemable_position.redeemable_shares = Wei(
            redeemable_position.amount - leaf_processed_shares
        )

    # Group positions by vault
    vault_to_positions: defaultdict[ChecksumAddress, list[RedeemablePosition]] = defaultdict(list)
    for position in redeemable_positions:
        vault_to_positions[position.vault].append(position)

    positions_to_redeem = []
    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None] = {}
    for vault_address, positions in vault_to_positions.items():
        # Check if state update is required
        harvest_params = await get_harvest_params(vault_address, block_number)
        vault_to_harvest_params[vault_address] = harvest_params
        withdrawable_assets = await get_withdrawable_assets(vault_address, harvest_params)

        #  Handle Meta-Vaults with Insufficient Withdrawable Assets
        vault_positions_shares = Wei(sum(position.redeemable_shares for position in positions))
        vault_positions_assets = os_token_converter.to_assets(vault_positions_shares)
        if vault_positions_assets > withdrawable_assets and await is_meta_vault(vault_address):
            # Check if vault is a meta-vault
            logger.info(
                'Vault %s is a meta-vault with insufficient withdrawable assets.', vault_address
            )
            additional_assets_needed = Wei(vault_positions_assets - withdrawable_assets)
            redeemed_assets = await os_token_redeemer_contract.redeem_sub_vaults_assets(
                vault_address, additional_assets_needed
            )
            withdrawable_assets = Wei(withdrawable_assets + redeemed_assets)

        # Process each position in the vault
        for position in positions:
            # Convert redeemable shares to assets
            redeemable_assets = os_token_converter.to_assets(position.redeemable_shares)

            if redeemable_assets <= withdrawable_assets:
                shares_to_redeem = min(position.amount, queued_shares)
                logger.info(
                    'Position Owner: %s, Vault: %s, Shares to Redeem: %s',
                    position.owner,
                    position.vault,
                    shares_to_redeem,
                )
                positions_to_redeem.append(
                    RedeemablePosition(
                        vault=position.vault,
                        owner=position.owner,
                        amount=position.amount,
                        redeemable_shares=shares_to_redeem,
                    )
                )
                withdrawable_assets = Wei(withdrawable_assets - redeemable_assets)
                queued_shares = Wei(queued_assets - shares_to_redeem)

    #  Execute Redemption with Multicall
    tx_hash = await execute_redemption(
        positions_to_redeem=positions_to_redeem,
        vault_to_harvest_params=vault_to_harvest_params,
        nonce=nonce,
    )
    logger.info(
        'Successfully redeemed %s OsToken positions. Transaction hash: %s',
        len(positions_to_redeem),
        tx_hash,
    )


async def execute_redemption(
    positions_to_redeem: list[RedeemablePosition],
    vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None],
    nonce: int,
) -> HexStr | None:

    multiproof = _get_multi_proof(
        positions_to_redeem=positions_to_redeem,
        nonce=nonce,
    )
    calls = []

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

    redeem_os_token_positions_call = os_token_redeemer_contract.encode_abi(
        fn_name='redeemOsTokenPositions',
        args=[positions_to_redeem, multiproof.proof, multiproof.proof_flags],
    )
    calls.append((os_token_redeemer_contract.contract_address, redeem_os_token_positions_call))
    try:
        tx_function = multicall_contract.functions.aggregate(calls)
        tx = await transaction_gas_wrapper(tx_function=tx_function)
    except Exception as e:
        logger.error('Failed to redeem os token positions: %s', e)
        logger.exception(e)
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


async def fetch_redeemable_positions(ipfs_hash: str) -> list[RedeemablePosition]:
    # Fetch redeemable positions data from IPFS
    data = cast(list[dict], await ipfs_fetch_client.fetch_json(ipfs_hash))

    # data structure example:
    # [{"owner:" 0x01, "amount": 100000, "vault": 0x02}, ...]

    return [
        RedeemablePosition(
            owner=Web3.to_checksum_address(item['owner']),
            vault=Web3.to_checksum_address(item['vault']),
            amount=Wei(int(item['amount'])),
        )
        for item in data
    ]


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
        logger.info('ProcessExitQueue transaction sent. Tx Hash: %s', tx_hash)


async def _startup_check() -> None:
    positions_manager = await os_token_redeemer_contract.positions_manager()
    if positions_manager != wallet.account.address:
        raise RuntimeError(
            f'The Position Manager role must be assigned to the address {wallet.account.address}.'
        )


def _get_multi_proof(
    nonce: int,
    positions_to_redeem: list[RedeemablePosition],
) -> MultiProof[tuple[bytes, int]]:
    leaves = [r.merkle_leaf(nonce) for r in positions_to_redeem]
    tree = StandardMerkleTree.of(
        leaves,
        [
            'uint256',
            'address',
            'uint256',
            'address',
        ],
    )
    multi_proof = tree.get_multi_proof(leaves)
    return multi_proof
