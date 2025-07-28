import logging

from sw_utils import InterruptHandler
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, HexStr, Wei

from src.common.app_state import AppState
from src.common.clients import execution_client
from src.common.contracts import RewardSplitterContract, RewardSplitterEncoder
from src.common.execution import build_gas_manager
from src.common.harvest import get_harvest_params
from src.common.tasks import BaseTask
from src.common.typings import HarvestParams
from src.common.wallet import hot_wallet
from src.config.networks import ZERO_CHECKSUM_ADDRESS
from src.config.settings import (
    REWARD_SPLITTER_INTERVAL,
    REWARD_SPLITTER_MIN_ASSETS,
    settings,
)
from src.reward_splitter.graph import (
    graph_get_claimable_exit_requests,
    graph_get_reward_splitters,
)
from src.reward_splitter.typings import ExitRequest, RewardSplitter

logger = logging.getLogger(__name__)


class SplitRewardTask(BaseTask):

    # pylint: disable-next=too-many-locals
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """
        Processes reward splitters for the vaults specified in settings.

        This function performs the following steps:
        - Retrieves reward splitters associated with the vaults from Subgraph.
        - Retrieves claimable exit requests for the reward splitters.
        - Calls reward splitter contracts and waits for transactions confirmations.
        """
        block = await execution_client.eth.get_block('finalized')

        app_state = AppState()
        if not await _check_reward_splitter_block(app_state, block['number']):
            return

        # check current gas prices
        gas_manager = build_gas_manager()
        if not await gas_manager.check_gas_price():
            return

        logger.info('Fetching reward splitters')
        reward_splitters = await graph_get_reward_splitters(
            block_number=block['number'], claimer=hot_wallet.account.address, vaults=settings.vaults
        )

        if not reward_splitters:
            logger.info(
                'No reward splitters found for provided vaults with the claimer %s',
                hot_wallet.address,
            )
            return
        splitter_to_exit_requests = await graph_get_claimable_exit_requests(
            block_number=block['number'], receivers=[rs.address for rs in reward_splitters]
        )

        calls: dict[ChecksumAddress, list[HexStr]] = {}
        for reward_splitter in reward_splitters:
            logger.info(
                'Processing reward splitter %s for vault %s',
                reward_splitter.address,
                reward_splitter.vault,
            )
            vault = reward_splitter.vault

            harvest_params = await get_harvest_params(vault)
            exit_requests = splitter_to_exit_requests.get(reward_splitter.address, [])  # nosec

            reward_splitter_calls = await _get_reward_splitter_calls(
                reward_splitter=reward_splitter,
                harvest_params=harvest_params,
                exit_requests=exit_requests,
            )

            calls[reward_splitter.address] = reward_splitter_calls
        if not calls:
            logger.warning('No calls to process')
            return

        logger.info('Processing reward splitter calls')
        for address, address_calls in calls.items():
            contract = RewardSplitterContract(
                address=address,
                execution_client=execution_client,
            )
            contract_func = contract.functions.multicall(address_calls)

            # Send transaction
            tx = await contract_func.transact()
            tx_hash = Web3.to_hex(tx)
            logger.info('Waiting for transaction %s confirmation', tx_hash)

            tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
                tx, timeout=settings.execution_transaction_timeout
            )
            if not tx_receipt['status']:
                raise RuntimeError(
                    f'Failed to confirm reward splitter tx: {tx_hash}',
                )
            logger.info('Transaction %s confirmed', tx_hash)

        app_state.reward_splitter_block = block['number']
        logger.info('All reward splitter calls processed')


async def _check_reward_splitter_block(app_state: AppState, block_number: BlockNumber) -> bool:
    last_processed_block = app_state.reward_splitter_block
    reward_splitter_blocks_interval = (
        REWARD_SPLITTER_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
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
    reward_splitter_encoder = _get_reward_splitter_encoder()

    reward_splitter_assets = await _get_reward_splitter_assets(reward_splitter)

    if reward_splitter_assets < REWARD_SPLITTER_MIN_ASSETS:
        logger.info(
            'Reward splitter %s does not have enough assets to withdraw', reward_splitter.address
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
        logger.info('No exit requests for reward splitter %s', reward_splitter.address)

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


def _get_reward_splitter_encoder() -> RewardSplitterEncoder:
    # Reward splitter contract is used to encode abi calls.
    # Not for sending transactions.
    # It's okay to put zero address here.
    reward_splitter_contract = RewardSplitterContract(
        address=ZERO_CHECKSUM_ADDRESS,
        execution_client=execution_client,
    )
    return reward_splitter_contract.encoder()
