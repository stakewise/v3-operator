import logging

from sw_utils import InterruptHandler

from src.common.execution import check_gas_price
from src.common.harvest import get_harvest_params
from src.common.tasks import BaseTask
from src.harvest.execution import submit_harvest_transaction

logger = logging.getLogger(__name__)


class HarvestTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """Check vault state and send harvest transaction if needed."""

        # check current gas prices
        if not await check_gas_price():
            return

        harvest_params = await get_harvest_params()
        if not harvest_params:
            return

        logger.info('Starting vault harvest')
        tx_hash = await submit_harvest_transaction(harvest_params)
        if not tx_hash:
            return
        logger.info('Successfully harvested vault')
