import logging

from eth_typing import HexStr
from web3 import Web3

from src.common.clients import execution_client
from src.common.contracts import vault_contract
from src.common.execution import get_max_fee_per_gas
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
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)
    return tx_hash


async def check_gas_price_for_harvest() -> bool:
    max_fee_per_gas = await get_max_fee_per_gas()
    if max_fee_per_gas >= Web3.to_wei(settings.max_fee_per_gas_gwei, 'gwei'):
        logging.warning(
            'Current gas price (%s gwei) is too high. '
            'Will try to harvest on the next block if the gas '
            'price is acceptable.',
            Web3.from_wei(max_fee_per_gas, 'gwei'),
        )
        return False

    return True
