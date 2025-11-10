import logging

from eth_typing import ChecksumAddress, HexStr
from hexbytes import HexBytes
from sw_utils import GNO_NETWORKS, InterruptHandler, convert_to_mgno
from web3 import Web3
from web3.types import BlockNumber

from src.common.app_state import AppState
from src.common.clients import execution_client
from src.common.contracts import (
    MetaVaultContract,
    VaultContract,
    keeper_contract,
    multicall_contract,
)
from src.common.execution import build_gas_manager
from src.common.tasks import BaseTask
from src.config.networks import ZERO_CHECKSUM_ADDRESS
from src.config.settings import (
    META_VAULT_MIN_DEPOSIT_AMOUNT,
    META_VAULT_UPDATE_INTERVAL,
    settings,
)
from src.meta_vault.exceptions import ClaimDelayNotPassedException
from src.meta_vault.graph import (
    graph_get_exit_requests_for_meta_vault,
    graph_get_vaults,
)
from src.meta_vault.typings import ContractCall, SubVaultExitRequest, Vault

logger = logging.getLogger(__name__)


class ProcessMetavaultTask(BaseTask):

    # pylint: disable-next=too-many-locals
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """
        Processes reward splitters for the vault specified in settings.

        This function performs the following steps:
        - Retrieves reward splitters associated with the vault from Subgraph.
        - Retrieves claimable exit requests for the reward splitters.
        - Calls reward splitter contracts and waits for transactions confirmations.
        """
        block = await execution_client.eth.get_block('finalized')

        app_state = AppState()
        if not await _check_metavault_block(app_state, block['number']):
            return

        logger.info('Fetching fee splitters')
        meta_vaults_map = await graph_get_vaults(
            is_meta_vault=True,
        )

        logger.info('Processing meta vault: %s', settings.vault)

        root_meta_vault = meta_vaults_map.get(settings.vault)
        if not root_meta_vault:
            app_state.metavault_update_block = block['number']
            logger.error('Meta vault %s not found in subgraph', settings.vault)
            return

        if not root_meta_vault.sub_vaults:
            logger.info('Meta vault %s has no sub vaults. Skipping.', settings.vault)
            app_state.metavault_update_block = block['number']
            return

        # check current gas prices
        gas_manager = build_gas_manager()
        if not await gas_manager.check_gas_price():
            return

        # Update the state for the entire meta vault tree
        try:
            await meta_vault_tree_update_state(
                root_meta_vault=root_meta_vault,
                meta_vaults_map=meta_vaults_map,
            )
        except ClaimDelayNotPassedException as e:
            logger.error(
                'Can not process meta vault %s because claim delay for exit request with '
                'position ticket %s has not passed yet',
                root_meta_vault.address,
                e.exit_request.position_ticket,
            )
            return

        # Deposit to sub vaults if there are withdrawable assets
        await process_deposit_to_sub_vaults(meta_vault_address=settings.vault)

        app_state.metavault_update_block = block['number']


async def _check_metavault_block(app_state: AppState, block_number: BlockNumber) -> bool:
    last_processed_block = app_state.metavault_update_block
    metavault_update_blocks_interval = (
        META_VAULT_UPDATE_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
    )
    if (
        last_processed_block
        and last_processed_block + metavault_update_blocks_interval >= block_number
    ):
        return False
    return True


async def meta_vault_tree_update_state(
    root_meta_vault: Vault,
    meta_vaults_map: dict[ChecksumAddress, Vault],
) -> None:
    """
    Update the state for the root meta vault and all its sub vaults.
    Sub vaults may themselves be meta vaults, so the update traverses the entire meta vault tree.
    """
    calls_with_description = await _get_meta_vault_tree_update_state_calls(
        root_meta_vault=root_meta_vault,
        meta_vaults_map=meta_vaults_map,
    )

    calls: list[tuple[ChecksumAddress, HexStr]] = []
    tx_steps: list[str] = []
    vaults_updated: set[ChecksumAddress] = set()

    for c in calls_with_description:
        calls.append((c.address, c.data))
        tx_steps.append(c.description)
        vaults_updated.add(c.address)

    if not calls:
        logger.info('Meta vault %s state is up-to-date, no updates needed', root_meta_vault.address)
        return

    # Submit the transaction
    logger.info(
        'Submitting transaction to update state for meta vault tree %s',
        root_meta_vault.address,
    )
    logger.info('Transaction steps: \n%s', '\n'.join(tx_steps))

    tx_hash = await multicall_contract.tx_aggregate(calls)

    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        HexBytes(Web3.to_bytes(hexstr=tx_hash)), timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        raise RuntimeError(
            f'Failed to confirm tx: {tx_hash}',
        )
    logger.info('Transaction %s confirmed', tx_hash)


async def _get_meta_vault_tree_update_state_calls(
    root_meta_vault: Vault,
    meta_vaults_map: dict[ChecksumAddress, Vault],
) -> list[ContractCall]:
    """
    Traverses meta vault tree and collects state update calls.
    """
    stack = [root_meta_vault.address]
    calls: list[ContractCall] = []

    while stack:
        # Take the last meta vault
        meta_vault_address = stack.pop()
        meta_vault = meta_vaults_map[meta_vault_address]

        if not meta_vault.sub_vaults:
            logger.info('Meta vault %s has no sub vaults. Skipping.', meta_vault.address)
            continue

        # Get calls for a single meta vault
        # skipping meta vaults among sub vaults.
        meta_vault_calls = await _get_meta_vault_update_state_calls(
            meta_vault=meta_vault,
        )

        # Insert new calls at the start
        calls = meta_vault_calls + calls

        # Schedule nested meta vaults for processing
        for sub_vault in meta_vault.sub_vaults:
            if sub_vault in meta_vaults_map:
                stack.append(sub_vault)
                continue

    return calls


async def _get_meta_vault_update_state_calls(
    meta_vault: Vault,
) -> list[ContractCall]:
    """
    Get state update calls for a single meta vault and its sub vaults.
    Skips meta vaults among sub vaults.
    Each call is a tuple of (vault_address, call_data, description).
    """
    logger.info('Getting state update calls for meta vault %s', meta_vault.address)

    # Get sub vaults
    sub_vaults = await graph_get_vaults(
        vaults=meta_vault.sub_vaults,
    )
    sub_vaults_to_harvest: list[ChecksumAddress] = []
    calls: list[ContractCall] = []

    # Vault contract
    vault_encoder = VaultContract(
        address=ZERO_CHECKSUM_ADDRESS,
    ).encoder()

    # Filter harvestable sub vaults and prepare calls for updating their state
    for sub_vault in sub_vaults.values():
        if not sub_vault.can_harvest:
            logger.info('Sub vault %s is not harvestable, skipping', sub_vault.address)
            continue

        # Handle nested meta vaults separately
        if sub_vault.is_meta_vault:
            logger.info('Sub vault %s is a meta vault, skipping', sub_vault.address)
            continue

        logger.info('Getting state update call for sub vault %s', sub_vault.address)
        sub_vaults_to_harvest.append(sub_vault.address)
        calls.append(
            ContractCall(
                address=sub_vault.address,
                data=vault_encoder.update_state(
                    sub_vault.harvest_params,
                ),
                description=f'Update state for sub vault {sub_vault.address}',
            )
        )

    # Collect claimable exit requests for the sub vaults
    sub_vault_exit_requests = await get_claimable_sub_vault_exit_requests(
        meta_vault_address=meta_vault.address,
    )

    # Meta vault contract
    meta_vault_contract = MetaVaultContract(
        address=meta_vault.address,
    )
    meta_vault_encoder = meta_vault_contract.encoder()

    # Claim sub vaults exited assets
    if sub_vault_exit_requests:
        logger.info(
            'Meta vault %s has %d sub vault exit requests to claim',
            meta_vault.address,
            len(sub_vault_exit_requests),
        )
        calls.append(
            ContractCall(
                address=meta_vault.address,
                data=meta_vault_encoder.claim_sub_vaults_exited_assets(sub_vault_exit_requests),
                description=f'Claim {len(sub_vault_exit_requests)} sub vault exit requests '
                f'for meta vault {meta_vault.address}',
            )
        )
    else:
        logger.info('No sub vault exit requests to claim for meta vault %s', meta_vault.address)

    # Update meta vault state
    is_rewards_nonce_outdated = await is_meta_vault_rewards_nonce_outdated(
        meta_vault_contract=meta_vault_contract,
    )

    if sub_vaults_to_harvest or is_rewards_nonce_outdated:
        calls.append(
            ContractCall(
                address=meta_vault.address,
                data=meta_vault_encoder.update_state(meta_vault.harvest_params),
                description=f'Update state for meta vault {meta_vault.address}',
            ),
        )
    return calls


async def get_claimable_sub_vault_exit_requests(
    meta_vault_address: ChecksumAddress,
) -> list[SubVaultExitRequest]:
    """
    Get claimable exit requests for the given sub vaults.
    """
    vault_to_exit_requests = await graph_get_exit_requests_for_meta_vault(
        meta_vault=meta_vault_address,
    )

    claimable_exit_requests: list[SubVaultExitRequest] = []

    for exit_requests in vault_to_exit_requests.values():
        for exit_request in exit_requests:
            if exit_request.is_waiting_for_claim_delay:
                raise ClaimDelayNotPassedException(exit_request)

            claimable_exit_requests.append(SubVaultExitRequest.from_exit_request(exit_request))

    return claimable_exit_requests


async def is_meta_vault_rewards_nonce_outdated(
    meta_vault_contract: MetaVaultContract,
) -> bool:
    """
    Check if the meta vault rewards nonce is outdated compared to the keeper contract.
    We can't read the rewards nonce from meta vault directly
    because it is stored in private attribute.
    Solution: compare events.
    """
    current_block = await execution_client.eth.get_block_number()

    # Find the last rewards updated event in the Keeper contract
    keeper_event = await keeper_contract.get_last_rewards_updated_event(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK, to_block=current_block
    )
    if keeper_event is None:
        logger.info('No RewardsUpdated event found in the Keeper contract')
        return False

    # Find the last rewards nonce updated event in the meta vault contract
    # since the last Keeper vote
    meta_vault_event = await meta_vault_contract.get_last_rewards_nonce_updated_event(
        from_block=BlockNumber(keeper_event['blockNumber'] + 1), to_block=current_block
    )

    # If no meta vault event is found, the rewards nonce is outdated
    return meta_vault_event is None


async def process_deposit_to_sub_vaults(meta_vault_address: ChecksumAddress) -> None:
    meta_vault_contract = MetaVaultContract(
        address=meta_vault_address,
    )
    withdrawable_assets = await meta_vault_contract.withdrawable_assets()

    if settings.network in GNO_NETWORKS:
        withdrawable_assets = convert_to_mgno(withdrawable_assets)

    logger.info(
        'Meta vault %s has withdrawable assets: %.2f %s',
        meta_vault_address,
        Web3.from_wei(withdrawable_assets, 'ether'),
        settings.network_config.VAULT_BALANCE_SYMBOL,
    )

    if withdrawable_assets < META_VAULT_MIN_DEPOSIT_AMOUNT:
        return

    logger.info('Depositing to sub vaults for meta vault %s', meta_vault_address)
    tx_hash = await meta_vault_contract.deposit_to_sub_vaults()

    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        HexBytes(Web3.to_bytes(hexstr=tx_hash)), timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        raise RuntimeError(
            f'Failed to confirm tx: {tx_hash}',
        )
    logger.info('Transaction %s confirmed', tx_hash)
