import logging

from src.common.contracts import keeper_contract
from src.common.execution import check_gas_price
from src.common.ipfs import fetch_harvest_params
from src.common.tasks import BaseTask
from src.config.settings import settings
from src.harvest.execution import submit_harvest_transaction

logger = logging.getLogger(__name__)


class HarvestTask(BaseTask):
    async def process_block(self) -> None:
        """Check vault state and send harvest transaction if needed."""
        if not await keeper_contract.can_harvest(settings.vault):
            return

        # check current gas prices
        if not await check_gas_price():
            return

        last_rewards = await keeper_contract.get_last_rewards_update()
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
        tx_hash = await submit_harvest_transaction(harvest_params)
        if not tx_hash:
            return
        logger.info('Successfully harvested vault')
