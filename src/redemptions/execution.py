import logging
from itertools import batched

from eth_typing import ChecksumAddress, HexStr
from web3 import Web3
from web3.contract.async_contract import AsyncContractFunction
from web3.exceptions import ContractCustomError

from src.common.contracts import VaultContract, multicall_contract
from src.common.execution import wait_for_execution_endpoints_synced
from src.common.harvest import get_multiple_harvest_params
from src.common.transaction import tx_manager
from src.common.utils import error_verbose
from src.config.settings import MULTICALL_CHUNK_SIZE
from src.meta_vault.service import is_meta_vault
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.typings import OsTokenPosition

logger = logging.getLogger(__name__)


async def update_vaults_state(
    vaults: list[ChecksumAddress],
) -> bool:
    """Bring every regular vault in ``vaults`` up to date on-chain via batched
    updateState multicalls.

    Meta vaults are skipped. Vaults are selected via ``can_harvest`` at the
    latest state. Fresh on-chain state lets ``get_withdrawable_assets`` (and
    position LTV) read accurate values without threading harvest_params through
    every call.

    Returns ``True`` when every vault is up to date, ``False`` when a multicall
    was not confirmed and some vaults are left with stale state.
    """
    logger.info('Processing vault state updates')
    regular_vaults: list[ChecksumAddress] = []
    for vault in vaults:
        if await is_meta_vault(vault):
            continue
        regular_vaults.append(vault)

    if not regular_vaults:
        return True

    vault_to_harvest_params = await get_multiple_harvest_params(regular_vaults)
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
        return True

    update_vaults = [address for address, _ in calls]
    logger.info(
        'Updating state for %d vaults: %s',
        len(update_vaults),
        ', '.join(update_vaults),
    )

    for chunk in batched(calls, MULTICALL_CHUNK_SIZE):
        if await tx_update_vaults_state(list(chunk)) is None:
            # Leave the remaining chunks for the next run.
            return False

    return True


async def tx_update_vaults_state(calls: list[tuple[ChecksumAddress, HexStr]]) -> HexStr | None:
    """Submit a single updateState multicall and wait for its receipt.

    Returns the tx hash on success, ``None`` when the tx was not submitted or
    not confirmed.
    """

    try:
        tx_receipt = await multicall_contract.tx_aggregate(calls)
    except Exception:  # pylint: disable=broad-except
        error_verbose('Failed to submit updateState multicall tx')
        return None

    if tx_receipt is None:
        logger.error('Failed to confirm updateState multicall tx')
        return None

    tx_hash = Web3.to_hex(tx_receipt['transactionHash'])
    logger.info('updateState multicall confirmed. Tx Hash: %s', tx_hash)
    return tx_hash


async def tx_process_exit_queue() -> None:
    """Call processExitQueue() on the redeemer contract."""
    tx_function = os_token_redeemer_contract.contract.functions.processExitQueue()
    try:
        tx_receipt = await tx_manager.transact(tx_function)
    except ContractCustomError as e:
        reason = os_token_redeemer_contract.decode_custom_error(str(e.data)) or e.data
        logger.error('Failed to process exit queue: execution reverted with %s', reason)
        return

    if tx_receipt is None:
        logger.error('Failed to confirm processExitQueue tx')
        return

    tx_hash = Web3.to_hex(tx_receipt['transactionHash'])
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
    except ContractCustomError as e:
        reason = os_token_redeemer_contract.decode_custom_error(str(e.data)) or e.data
        logger.error(
            'Failed to simulate redeem position (vault %s, owner %s): '
            'execution reverted with %s',
            position.vault,
            position.owner,
            reason,
        )
        return False
    except Exception as e:  # pylint: disable=broad-except
        logger.error(
            'Failed to simulate redeem position (vault %s, owner %s): %r',
            position.vault,
            position.owner,
            e,
        )
        return False
    logger.debug(
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
        tx_receipt = await tx_manager.transact(tx_function)
    except ContractCustomError as e:
        reason = os_token_redeemer_contract.decode_custom_error(str(e.data)) or e.data
        logger.error(
            'Failed to redeem position (vault %s, owner %s): execution reverted with %s',
            position.vault,
            position.owner,
            reason,
        )
        return False
    except Exception:  # pylint: disable=broad-except
        error_verbose(
            'Failed to redeem position (vault %s, owner %s)',
            position.vault,
            position.owner,
        )
        return False

    if tx_receipt is None:
        logger.error(
            'Failed to confirm redeem position tx (vault %s, owner %s)',
            position.vault,
            position.owner,
        )
        return False

    tx_hash = Web3.to_hex(tx_receipt['transactionHash'])
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
