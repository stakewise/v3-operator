import logging

from web3 import Web3
from web3.contract.async_contract import AsyncContractFunction
from web3.exceptions import Web3Exception

from src.common.clients import execution_client
from src.common.execution import (
    transaction_gas_wrapper,
    wait_for_execution_endpoints_synced,
)
from src.config.settings import settings
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.typings import OsTokenPosition

logger = logging.getLogger(__name__)


async def tx_process_exit_queue() -> None:
    """Call processExitQueue() on the redeemer contract."""
    tx_hash = await os_token_redeemer_contract.process_exit_queue()
    logger.info('Waiting for processExitQueue transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx_hash, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('processExitQueue transaction failed. Tx Hash: %s', tx_hash)
    else:
        logger.info('processExitQueue confirmed. Tx Hash: %s', tx_hash)


async def simulate_redeem_position(
    position: OsTokenPosition,
    tree: PositionsMerkleTree,
) -> bool:
    """Simulate one redeemOsTokenPositions transaction via ``.call()`` without submitting.

    Returns ``True`` when the call would succeed, ``False`` otherwise.
    """
    tx_function = _build_redeem_tx_function(position, tree)

    try:
        await tx_function.call()
    except (Web3Exception, RuntimeError, ValueError) as e:
        logger.error(
            'Failed to simulate redeem position (vault %s, owner %s): %r',
            position.vault,
            position.owner,
            e,
        )
        return False
    logger.info(
        'Simulated redeeming %s shares for position (vault %s, owner %s) successfully',
        position.shares_to_redeem,
        position.vault,
        position.owner,
    )
    return True


async def tx_redeem_position(
    position: OsTokenPosition,
    tree: PositionsMerkleTree,
) -> bool:
    """Submit one redeemOsTokenPositions transaction for a single position.

    Returns ``True`` on success, ``False`` otherwise.
    """
    tx_function = _build_redeem_tx_function(position, tree)

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


def _build_redeem_tx_function(
    position: OsTokenPosition, tree: PositionsMerkleTree
) -> AsyncContractFunction:
    """Build the redeemOsTokenPositions contract function for a single position."""
    multiproof = tree.get_multi_proof([position])
    positions_arg = [
        (position.vault, position.owner, position.leaf_shares, position.shares_to_redeem)
    ]
    return os_token_redeemer_contract.contract.functions.redeemOsTokenPositions(
        positions_arg, multiproof.proof, multiproof.proof_flags
    )
