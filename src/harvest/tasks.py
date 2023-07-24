import logging

from src.common.execution import (
    can_harvest,
    check_gas_price,
    check_hot_wallet_balance,
    get_last_rewards_update,
)
from src.common.ipfs import fetch_harvest_params
from src.config.settings import settings
from src.harvest.execution import submit_harvest_transaction

logger = logging.getLogger(__name__)


async def harvest_vault() -> None:
    """Check vault state and send harvest transaction if needed."""

    if not await can_harvest(settings.vault):
        return

    # check current gas prices
    if not await check_gas_price():
        return

    last_rewards = await get_last_rewards_update()
    if not last_rewards:
        return
    harvest_params = await fetch_harvest_params(
        vault_address=settings.vault,
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
