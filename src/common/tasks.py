import logging
import time

from sw_utils import InterruptHandler

from src.common.clients import execution_client
from src.common.consensus import get_chain_finalized_head
from src.common.metrics import metrics
from src.common.utils import log_verbose
from src.config.settings import settings

logger = logging.getLogger(__name__)


class BaseTask:
    async def run(self, interrupt_handler: InterruptHandler) -> None:
        while not interrupt_handler.exit:
            start_time = time.time()
            try:
                await self.process_block(interrupt_handler)
            except Exception as exc:
                metrics.exception_count.labels(network=settings.network).inc()
                log_verbose(exc)

            block_processing_time = time.time() - start_time
            sleep_time = max(
                float(settings.network_config.SECONDS_PER_BLOCK) - block_processing_time, 0
            )
            await interrupt_handler.sleep(sleep_time)

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        raise NotImplementedError


class MetricsTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        metrics.set_app_version()

        chain_state = await get_chain_finalized_head()
        latest_block_number = await execution_client.eth.get_block_number()

        metrics.block_number.labels(network=settings.network).set(latest_block_number)
        metrics.slot_number.labels(network=settings.network).set(chain_state.slot)
