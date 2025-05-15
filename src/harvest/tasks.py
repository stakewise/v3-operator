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
        if not await gas_manager.check_gas_price():
            return
        for vault_address in settings.vaults:
            harvest_params = await get_harvest_params(vault_address=vault_address)
            if not harvest_params:
                return

            logger.info('Starting vault %s harvest', vault_address)

            tx_hash = await submit_harvest_transaction(
                vault_address=vault_address, harvest_params=harvest_params
            )

            if not tx_hash:
                return
            logger.info('Successfully harvested vault %s', vault_address)
