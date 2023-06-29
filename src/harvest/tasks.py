import logging

from web3 import Web3

from src.common.execution import (
    can_harvest,
    check_hot_wallet_balance,
    get_last_rewards_update,
    get_max_fee_per_gas,
)
from src.common.ipfs import fetch_harvest_params
from src.config.settings import settings
from src.harvest.execution import submit_harvest_transaction

logger = logging.getLogger(__name__)


async def harvest_vault() -> None:
    """Check vault state and send harvest transaction if needed."""

    if not await can_harvest(settings.VAULT):
        return

    # check current gas prices
    max_fee_per_gas = await get_max_fee_per_gas()
    if max_fee_per_gas >= Web3.to_wei(settings.MAX_FEE_PER_GAS_GWEI, 'gwei'):
        logging.warning(
            'Current gas price (%s gwei) is too high. '
            'Will try to harvest on the next block if the gas '
            'price is acceptable.',
            Web3.from_wei(max_fee_per_gas, 'gwei'),
        )
        return

    last_rewards = await get_last_rewards_update()
    harvest_params = await fetch_harvest_params(
        vault_address=settings.VAULT,
        ipfs_hash=last_rewards.ipfs_hash,
        rewards_root=last_rewards.rewards_root,
    )
    if not harvest_params:
        return

    logger.info('Starting vault harvest')
    await submit_harvest_transaction(harvest_params)
    logger.info('Successfully harvested vault')

    # check balance after transaction
    await check_hot_wallet_balance()
