import logging

from sw_utils import InterruptHandler
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, HexStr, Wei

from src.common.app_state import AppState
from src.common.clients import execution_client
from src.common.contracts import RewardSplitterContract, RewardSplitterEncoder
from src.common.execution import check_gas_price, transaction_gas_wrapper
from src.common.harvest import get_harvest_params
from src.common.tasks import BaseTask
from src.common.typings import ExitRequest, HarvestParams
from src.common.wallet import wallet
from src.config.settings import FEE_SPLITTER_INTERVAL, FEE_SPLITTER_MIN_ASSETS, settings
from src.reward_splitter.graph import (
    graph_get_claimable_exit_requests,
    graph_get_reward_splitters,
)
from src.reward_splitter.typings import RewardSplitter

logger = logging.getLogger(__name__)


class SplitRewardTask(BaseTask):

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """
        Processes reward splitters for the vault specified in settings.

        Retrieves the reward splitters and their claimable exit requests from the
        Subgraph, then submits the claim calls on behalf of the shareholders.
        """
        await claim_reward_splitters(vaults=[settings.vault], update_vault_state=True)


async def claim_reward_splitters(
    vaults: list[ChecksumAddress],
    update_vault_state: bool,
) -> None:
    """
    Claim fee splitter rewards on behalf of shareholders for the given vaults.

    Interval-gated via AppState.reward_splitter_block so it runs roughly once per
    FEE_SPLITTER_INTERVAL. Set update_vault_state=False to skip the splitter-side
    updateVaultState call (e.g. for meta vaults whose state was already refreshed
    by the meta vault tree update).
    """
    block = await execution_client.eth.get_block('finalized')

    app_state = AppState()
    if not await _check_reward_splitter_block(app_state, block['number']):
        return

    logger.info('Fetching fee splitters')

    harvest_params = await get_harvest_params() if update_vault_state else None

    all_succeeded = True
    for vault in vaults:
        try:
            succeeded = await claim_reward_splitters_for_vault(
                vault=vault,
                block_number=block['number'],
                harvest_params=harvest_params,
            )
        except Exception:
            logger.exception('Failed to claim fee splitters for vault %s', vault)
            succeeded = False
        all_succeeded = all_succeeded and succeeded

    # Advance the interval marker only when no vault was blocked by gas price,
    # so a skipped claim is retried on the next loop instead of waiting a full interval.
    if all_succeeded:
        app_state.reward_splitter_block = block['number']


# pylint: disable-next=too-many-locals
async def claim_reward_splitters_for_vault(
    vault: ChecksumAddress,
    block_number: BlockNumber,
    harvest_params: HarvestParams | None,
) -> bool:
    """
    Claim fee splitter rewards on behalf of shareholders for a single vault.

    Fetches the fee splitters where the operator wallet is the configured claimer,
    builds the enterExitQueueOnBehalf and claimExitedAssetsOnBehalf multicalls, and
    submits them. Pass harvest_params=None to skip the splitter-side updateVaultState
    call.

    Returns False if the transactions were skipped because the gas price is too high,
    True otherwise.
    """
    reward_splitters = await graph_get_reward_splitters(
        block_number=block_number, claimer=wallet.account.address, vault=vault
    )

    if not reward_splitters:
        logger.warning(
            'No fee splitters found for vault %s with the claimer %s',
            vault,
            wallet.address,
        )
        return True

    splitter_to_exit_requests = await graph_get_claimable_exit_requests(
        block_number=block_number, receivers=[rs.address for rs in reward_splitters]
    )

    calls: dict[ChecksumAddress, list[HexStr]] = {}
    for reward_splitter in reward_splitters:
        logger.info(
            'Processing fee splitter %s',
            reward_splitter.address,
        )
        exit_requests = splitter_to_exit_requests.get(reward_splitter.address, [])  # nosec

        reward_splitter_calls = await _get_reward_splitter_calls(
            reward_splitter=reward_splitter,
            harvest_params=harvest_params,
            exit_requests=exit_requests,
        )
        if not reward_splitter_calls:
            logger.info('No calls to process for fee splitter %s', reward_splitter.address)
            continue

        calls[reward_splitter.address] = reward_splitter_calls

    if not calls:
        return True

    # check current gas prices
    if not await check_gas_price():
        return False

    logger.info('Processing fee splitter calls')
    for address, address_calls in calls.items():
        contract = RewardSplitterContract(
            address=address,
            execution_client=execution_client,
        )
        tx_function = contract.functions.multicall(address_calls)
        tx = await transaction_gas_wrapper(tx_function)
        tx_hash = Web3.to_hex(tx)
        logger.info('Waiting for transaction %s confirmation', tx_hash)

        tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
            tx, timeout=settings.execution_transaction_timeout
        )
        if not tx_receipt['status']:
            raise RuntimeError(
                f'Failed to confirm fee splitter tx: {tx_hash}',
            )
        logger.info('Transaction %s confirmed', tx_hash)

    logger.info('All fee splitter calls processed')
    return True


async def _check_reward_splitter_block(app_state: AppState, block_number: BlockNumber) -> bool:
    last_processed_block = app_state.reward_splitter_block
    reward_splitter_blocks_interval = (
        FEE_SPLITTER_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
    )
    if (
        last_processed_block
        and last_processed_block + reward_splitter_blocks_interval >= block_number
    ):
        return False
    return True


async def _get_reward_splitter_calls(
    reward_splitter: RewardSplitter,
    harvest_params: HarvestParams | None,
    exit_requests: list[ExitRequest],
) -> list[HexStr]:
    """
    Generate ABI encoded calls for the reward splitter contract.

    It includes calls:
    1. for updating the vault state,
    2. entering the exit queue on behalf of shareholders,
    3. claiming exited assets on behalf of shareholders.

    Returns:
        list[HexStr]: A list of ABI encoded calls for the reward splitter contract.
    """
    # ABI encoded calls without contract address
    reward_splitter_calls: list[HexStr] = []
    reward_splitter_encoder = RewardSplitterEncoder()

    reward_splitter_assets = await _get_reward_splitter_assets(reward_splitter)

    if reward_splitter_assets < FEE_SPLITTER_MIN_ASSETS:
        logger.info(
            'Fee splitter %s does not have enough assets to withdraw', reward_splitter.address
        )
    else:
        # Append update state call
        if harvest_params:
            reward_splitter_calls.append(
                reward_splitter_encoder.update_vault_state(harvest_params=harvest_params)
            )

        # Append enter exit queue on behalf calls
        for shareholder in reward_splitter.shareholders:
            logger.debug('Processing shareholder %s', shareholder.address)

            reward_splitter_calls.append(
                reward_splitter_encoder.enter_exit_queue_on_behalf(
                    rewards=None,  # exiting all rewards
                    address=shareholder.address,
                )
            )

    # Append claim exited assets on behalf calls
    if not exit_requests:
        logger.info('No exit requests for fee splitter %s', reward_splitter.address)

    for exit_request in exit_requests:
        logger.info('Processing exit request with position ticket %s', exit_request.position_ticket)
        if exit_request.exit_queue_index is None:
            logger.error(
                'Exit request with position ticket %s does not have an exit queue index',
                exit_request.position_ticket,
            )
            continue
        reward_splitter_calls.append(
            reward_splitter_encoder.claim_exited_assets_on_behalf(
                position_ticket=exit_request.position_ticket,
                timestamp=exit_request.timestamp,
                exit_queue_index=exit_request.exit_queue_index,
            ),
        )

    return reward_splitter_calls


async def _get_reward_splitter_assets(reward_splitter: RewardSplitter) -> Wei:
    return Wei(sum(sh.earned_vault_assets for sh in reward_splitter.shareholders))
