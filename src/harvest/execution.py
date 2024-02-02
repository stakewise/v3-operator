import logging

from eth_typing import HexStr
from web3 import Web3

from src.common.clients import execution_client
from src.common.contracts import vault_contract
from src.common.typings import HarvestParams
from src.common.utils import format_error
from src.config.networks import ETH_NETWORKS
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_harvest_transaction(harvest_params: HarvestParams) -> HexStr | None:
    if settings.network not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    logger.info('Submitting harvest transaction...')
    try:
        tx = await vault_contract.functions.updateState(
            (
                harvest_params.rewards_root,
                harvest_params.reward,
                harvest_params.unlocked_mev_reward,
                harvest_params.proof,
            )
        ).transact()
    except Exception as e:
        logger.error('Failed to harvest: %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for transaction %s confirmation', tx_hash)
    await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    return tx_hash
