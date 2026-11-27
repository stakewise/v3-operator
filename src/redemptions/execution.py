import logging
from itertools import batched

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import is_meta_vault_upgraded_to_release
from sw_utils.networks import ContractReleaseVersion
from web3 import Web3
from web3.contract.async_contract import AsyncContractFunction
from web3.types import Wei

from src.common.contracts import VaultContract, multicall_contract
from src.common.execution import wait_for_execution_endpoints_synced
from src.common.harvest import get_multiple_harvest_params
from src.common.transaction import simulate_checked, transact_checked
from src.common.utils import error_verbose, format_error
from src.config.settings import MULTICALL_CHUNK_SIZE, settings
from src.meta_vault.graph import graph_get_vaults
from src.meta_vault.service import is_meta_vault
from src.meta_vault.tasks import meta_vault_tree_update_state
from src.redemptions.contracts import os_token_redeemer_contract
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.typings import OsTokenPosition

logger = logging.getLogger(__name__)


async def update_vaults_state(
    vaults: list[ChecksumAddress],
) -> bool:
    """Bring every vault in ``vaults`` up to date on-chain.

    Meta vaults are harvested first, each together with its sub-vault tree.
    A meta vault that fails to update is left stale: redeem_positions skips it.
    Regular vaults are then selected via ``can_harvest`` at the latest state and
    updated via batched updateState multicalls. Fresh on-chain state lets
    ``get_withdrawable_assets`` (and position LTV) read accurate values without
    threading harvest_params through every call.

    Returns ``True`` when every regular vault is up to date, ``False`` when a
    multicall was not confirmed and some vaults are left with stale state.
    """
    logger.info('Processing vault state updates')
    regular_vaults: list[ChecksumAddress] = []
    meta_vaults: list[ChecksumAddress] = []
    for vault in vaults:
        if await is_meta_vault(vault):
            meta_vaults.append(vault)
        else:
            regular_vaults.append(vault)

    # Harvesting a meta vault tree also updates its sub vaults,
    # so do it before selecting harvestable regular vaults.
    await update_meta_vaults_state(meta_vaults)

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


async def update_meta_vaults_state(meta_vaults: list[ChecksumAddress]) -> None:
    """Update state of every meta vault tree in ``meta_vaults``, bottom-up.
    Failures are logged and leave the meta vault stale."""
    if not meta_vaults:
        return

    meta_vaults_map = await graph_get_vaults(is_meta_vault=True)
    for vault in meta_vaults:
        root_meta_vault = meta_vaults_map.get(vault)
        if root_meta_vault is None:
            logger.error('Meta vault %s not found in subgraph', vault)
            continue
        if not is_meta_vault_upgraded_to_release(
            network=settings.network,
            vault_address=vault,
            vault_version=root_meta_vault.version,
            release_version=ContractReleaseVersion.V5,
        ):
            logger.warning('Meta vault %s is not upgraded to contracts release v5', vault)
            continue
        if not root_meta_vault.sub_vaults:
            continue
        try:
            await meta_vault_tree_update_state(
                root_meta_vault=root_meta_vault,
                meta_vaults_map=meta_vaults_map,
            )
        except Exception as e:  # pylint: disable=broad-except
            error_verbose(
                'Failed to update meta vault tree state for vault %s: %s', vault, format_error(e)
            )


async def tx_update_vaults_state(calls: list[tuple[ChecksumAddress, HexStr]]) -> HexStr | None:
    """Submit a single updateState multicall and wait for its receipt.

    Returns the tx hash on success, ``None`` when the tx was not submitted or
    not confirmed.
    """
    tx_receipt = await multicall_contract.tx_aggregate(calls)
    if tx_receipt is None:
        return None

    tx_hash = Web3.to_hex(tx_receipt['transactionHash'])
    logger.info('updateState multicall confirmed. Tx Hash: %s', tx_hash)
    return tx_hash


async def tx_process_exit_queue() -> None:
    """Call processExitQueue() on the redeemer contract."""
    tx_function = os_token_redeemer_contract.contract.functions.processExitQueue()
    tx_receipt = await transact_checked(
        tx_function, contract=os_token_redeemer_contract, action='process exit queue'
    )
    if tx_receipt is None:
        return

    tx_hash = Web3.to_hex(tx_receipt['transactionHash'])
    logger.info('processExitQueue confirmed. Tx Hash: %s', tx_hash)


async def tx_redeem_sub_vaults_assets(
    meta_vault: ChecksumAddress, assets_to_redeem: Wei
) -> BlockNumber | None:
    """Call redeemSubVaultsAssets() on the redeemer contract to move assets
    from the meta vault's sub vaults into the meta vault.

    Returns the receipt block number on success, ``None`` otherwise.
    """
    tx_function = os_token_redeemer_contract.contract.functions.redeemSubVaultsAssets(
        meta_vault, assets_to_redeem
    )
    tx_receipt = await transact_checked(
        tx_function,
        contract=os_token_redeemer_contract,
        action=f'redeem sub vaults assets for meta vault {meta_vault}',
    )
    if tx_receipt is None:
        return None

    tx_hash = Web3.to_hex(tx_receipt['transactionHash'])
    logger.info(
        'redeemSubVaultsAssets confirmed for meta vault %s. Tx Hash: %s', meta_vault, tx_hash
    )
    return tx_receipt['blockNumber']


async def simulate_redeem_position(
    position: OsTokenPosition,
    tree: PositionsMerkleTree,
) -> bool:
    """Simulate one redeemOsTokenPositions transaction via ``.call()`` without submitting.

    Returns ``True`` when the call would succeed, ``False`` otherwise.
    """
    tx_function = _build_redeem_tx_function(position, tree)
    if not await simulate_checked(
        tx_function,
        contract=os_token_redeemer_contract,
        action=f'simulate redeem position (vault {position.vault}, owner {position.owner})',
    ):
        return False

    logger.debug(
        'Simulated redeeming %(shares)s shares (%(os_token)s) '
        'for position (vault %(vault)s, owner %(owner)s) successfully',
        {
            'shares': position.shares_to_redeem,
            'os_token': format_os_token_shares(position.shares_to_redeem),
            'vault': position.vault,
            'owner': position.owner,
        },
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
    tx_receipt = await transact_checked(
        tx_function,
        contract=os_token_redeemer_contract,
        action=f'redeem position (vault {position.vault}, owner {position.owner})',
    )
    if tx_receipt is None:
        return False

    tx_hash = Web3.to_hex(tx_receipt['transactionHash'])
    logger.info(
        'Redeemed %(shares)s shares (%(os_token)s) '
        'for position (vault %(vault)s, owner %(owner)s). Tx Hash: %(tx_hash)s',
        {
            'shares': position.shares_to_redeem,
            'os_token': format_os_token_shares(position.shares_to_redeem),
            'vault': position.vault,
            'owner': position.owner,
            'tx_hash': tx_hash,
        },
    )
    # Barrier against fallback endpoints lagging behind the receipt block.
    await wait_for_execution_endpoints_synced(tx_receipt['blockNumber'])
    return True


def format_os_token_shares(shares: int) -> str:
    """Human-readable osToken amount, e.g. '4.767899607186542728 osETH'."""
    return f'{Web3.from_wei(shares, 'ether')} {settings.network_config.OS_TOKEN_BALANCE_SYMBOL}'


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
