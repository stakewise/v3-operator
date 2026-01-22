import asyncio
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import cast

import click
from eth_typing import ChecksumAddress
from multiproof.standard import standard_leaf_hash
from web3 import Web3
from web3.types import Wei

from src.common.clients import execution_client, ipfs_fetch_client, setup_clients
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
from src.redeem.os_token_converter import create_os_token_converter
from src.redeem.typings import OsTokenPosition, RedeemablePosition
from src.validators.execution import get_withdrawable_assets

logger = logging.getLogger(__name__)


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
@click.command(help='Updates redeemable positions')
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
    Fetch redeemable positions, calculate kept os token amounts and upload to IPFS.
    """
    setup_logging()
    await setup_clients()
    await _startup_check()

    while True:
        block_number = await execution_client.eth.block_number
        # Check Exit Queue Processing
        can_process_exit_queue = await os_token_redeemer_contract.can_process_exit_queue(
            block_number
        )
        if can_process_exit_queue:
            logger.info('Exit queue can be processed. Calling processExitQueue...')
            tx_hash = await os_token_redeemer_contract.process_exit_queue()
            logger.info('ProcessExitQueue transaction sent. Tx Hash: %s', tx_hash.hex())

        # Check Queued Shares for Redemption
        queued_shares = await os_token_redeemer_contract.queued_shares(block_number)
        if queued_shares == 0:
            logger.info('No queued shares for redemption. Skipping to next interval.')
            await asyncio.sleep(300)  # Sleep for 5 minutes before next check
            continue

        os_token_converter = await create_os_token_converter(block_number)
        queued_assets = os_token_converter.to_assets(queued_shares)

        # Fetch Positions from IPFS
        redeemable_positions_meta = await os_token_redeemer_contract.redeemable_positions(
            block_number
        )
        redeemable_positions = await fetch_redeemable_positions(redeemable_positions_meta.ipfs_hash)

        # Calculate Redeemable Shares Per Position
        for redeemable_position in redeemable_positions:
            # Compute leaf hash
            leaf_hash = get_redeemable_position_leaf_hash(
                redeemable_position=redeemable_position, nonce=redeemable_positions_meta.nonce - 1
            )

            # Get already processed shares
            processed_shares = await os_token_redeemer_contract.leaf_to_processed_shares(
                leaf_hash, block_number
            )

            # Calculate redeemable shares
            redeemable_position.redeemable_shares = redeemable_position.amount - processed_shares

        # Filter Positions by Vault Withdrawable Assets

        # Group positions by vault
        vault_to_positions: defaultdict[ChecksumAddress, list[RedeemablePosition]] = defaultdict(
            list
        )
        for position in redeemable_positions:
            vault_to_positions[position.vault].append(position)

        processing_positions = []
        vault_to_harvest_params: dict[ChecksumAddress, HarvestParams | None] = {}
        for vault_address, positions in vault_to_positions.items():
            # Check if state update is required
            harvest_params = await get_harvest_params(vault_address, block_number)
            vault_to_harvest_params[vault_address] = harvest_params
            withdrawable_assets = await get_withdrawable_assets(vault_address, harvest_params)

            # Process each position in the vault
            for position in positions:
                # Convert redeemable shares to assets
                redeemable_assets = os_token_converter.to_assets(position.redeemable_shares)

                if redeemable_assets <= withdrawable_assets:
                    shares_to_redeem = min(position.amount, queued_shares)
                    logger.info(
                        f"Position Owner: {position.owner}, "
                        f"Vault: {position.vault}, "
                        f"Shares to Redeem: {shares_to_redeem}"
                    )
                    processing_positions.append(
                        OsTokenPosition(
                            vault=position.vault,
                            owner=position.owner,
                            leaf_shares=position.amount,
                            shares_to_redeem=shares_to_redeem,
                        )
                    )
                    withdrawable_assets -= redeemable_assets
                    queued_shares -= shares_to_redeem

        #  Handle Meta-Vaults with Insufficient Withdrawable Assets
        #  Execute Redemption with Multicall
        await execute_redemption(
            redeemed_positions=processing_positions,
            vault_to_harvest_params=vault_to_harvest_params,
        )


async def execute_redemption(
    redeemed_positions: list[OsTokenPosition],
    vault_to_harvest_params: HarvestParams | None,
) -> None:
    calls = []

    for vault in set(pos.vault for pos in redeemed_positions):
        harvest_params = vault_to_harvest_params.get(vault)
        if harvest_params:
            vault_contract = VaultContract(vault)
            calls.append(
                [
                    (
                        vault_contract.contract_address,
                        vault_contract.get_update_state_call(harvest_params),
                    )
                ]
            )

    redeem_os_token_positions_call = os_token_redeemer_contract.encode_abi(
        fn_name='redeemOsTokenPositions',
        args=[redeemed_positions, proof, proofFlags],
    )
    calls.append((os_token_redeemer_contract.address, redeem_os_token_positions_call))
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
        logger.error(logger.error('Failed to redeem os token positions...'))
        return None

    return tx_hash


def get_redeemable_position_leaf_hash(redeemable_position: RedeemablePosition, nonce: int) -> bytes:
    """Get the leaf hash for a redeemable position."""
    vault = redeemable_position.vault
    owner = redeemable_position.owner
    amount = redeemable_position.amount

    leaf = standard_leaf_hash(
        values=(nonce, vault, amount, owner),
        types=['uint256', 'address', 'uint256', 'address'],
    )
    return leaf


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


async def _startup_check() -> None:
    positions_manager = await os_token_redeemer_contract.positions_manager()
    if positions_manager != wallet.account.address:
        raise RuntimeError(
            f'The Position Manager role must be assigned to the address {wallet.account.address}.'
        )
