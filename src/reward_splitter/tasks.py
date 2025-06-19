import logging
from typing import cast

from sw_utils import InterruptHandler, chunkify
from web3.types import ChecksumAddress, HexBytes, HexStr, Web3

from src.common.clients import execution_client
from src.common.execution import build_gas_manager
from src.common.tasks import BaseTask
from src.config.settings import settings
from src.reward_splitter.contracts import RewardSplitterContract, RewardSplitterEncoder
from src.reward_splitter.graph import (
    graph_get_claimable_exit_requests,
    graph_get_reward_splitters,
    graph_get_vaults,
)
from src.reward_splitter.typings import ExitRequest, RewardSplitter

logger = logging.getLogger(__name__)


class SplitRewardTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """
        Processes reward splitters for the vaults specified in settings.

        This function performs the following steps:
        1. Fetches the list of vaults from Subgraph.
        2. Retrieves reward splitters associated with the vaults from Subgraph.
        3. Maps the vaults to their harvest params.
        4. Retrieves claimable exit requests for the reward splitters.
        5. Generates multicall contract calls for each reward splitter.
        6. Processes the multicall batches and waits for transaction confirmations.

        Raises:
            RuntimeError: If a transaction fails to confirm.
        """

        # check current gas prices
        gas_manager = build_gas_manager()
        if not await gas_manager.check_gas_price():
            return

        block = await execution_client.eth.get_block('finalized')

        logger.info('Fetching reward splitters')
        reward_splitters = await graph_get_reward_splitters(
            block_number=block['number'], vaults=settings.vaults
        )

        if not reward_splitters:
            logger.info('No reward splitters found for given vaults')
            return

        vaults = [rs.vault for rs in reward_splitters]

        graph_vaults_map = await graph_get_vaults(vaults=vaults)

        splitter_to_exit_requests = await graph_get_claimable_exit_requests(
            block_number=block['number'], receivers=[rs.address for rs in reward_splitters]
        )

        # Multicall contract calls
        calls: list[tuple[ChecksumAddress, HexStr]] = []

        for reward_splitter in reward_splitters:
            logger.info(
                'Processing reward splitter %s for vault %s',
                reward_splitter.address,
                reward_splitter.vault,
            )
            vault = reward_splitter.vault

            graph_vault = graph_vaults_map[vault]
            can_harvest = graph_vault.can_harvest
            harvest_params = graph_vault.harvest_params
            exit_requests = splitter_to_exit_requests.get(reward_splitter.address, [])  # nosec

            reward_splitter_calls = await _get_reward_splitter_calls(
                reward_splitter=reward_splitter,
                can_harvest=can_harvest,
                harvest_params=harvest_params,
                exit_requests=exit_requests,
            )

            # Add up to multicall format calls
            calls.extend([(reward_splitter.address, call) for call in reward_splitter_calls])

        if not calls:
            logger.warning('No calls to process')
            return

        for calls_batch in chunkify(calls, settings.MULTICALL_BATCH_SIZE):
            logger.info('Processing multicall batch')
            tx = await _multicall(calls_batch)

            if settings.DRY_RUN:
                continue

            tx = cast(HexBytes, tx)
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

        logger.info('All multicall batches processed')
