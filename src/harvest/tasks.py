import logging

from sw_utils import InterruptHandler

from src.common.execution import build_gas_manager
from src.common.harvest import get_harvest_params
from src.common.tasks import BaseTask
from src.config.settings import settings
from src.harvest.execution import submit_harvest_transaction

logger = logging.getLogger(__name__)


class HarvestTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """
        Check vault state and send harvest transaction if needed.
        For Gnosis vaults: swap xDAI to GNO.
        """

        # check current gas prices
        gas_manager = build_gas_manager()
        harvest_params = await get_harvest_params()
        if not harvest_params:
            return

        if not await gas_manager.check_gas_price():
            return

        logger.info('Starting vault %s harvest', settings.vault)

        tx_hash = await submit_harvest_transaction(harvest_params=harvest_params)

        if not tx_hash:
            return
        logger.info('Successfully harvested')
