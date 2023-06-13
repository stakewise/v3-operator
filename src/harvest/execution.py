import logging

from sw_utils.decorators import backoff_aiohttp_errors
from web3 import Web3

from src.common.clients import execution_client
from src.common.contracts import VaultContract
from src.common.typings import HarvestParams
from src.config.networks import ETH_NETWORKS
from src.config.settings import DEFAULT_RETRY_TIME, settings

logger = logging.getLogger(__name__)


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def submit_harvest_transaction(harvest_params: HarvestParams) -> None:
    if settings.NETWORK not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    logger.info('Submitting harvest transaction...')
    tx = await VaultContract().contract.functions.updateState(
        (
            harvest_params.rewards_root,
            harvest_params.reward,
            harvest_params.unlocked_mev_reward,
            harvest_params.proof,
        )
    ).transact()  # type: ignore
    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)  # type: ignore
