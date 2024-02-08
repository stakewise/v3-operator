import logging
import time

from sw_utils import InterruptHandler

from src.common.utils import log_verbose
from src.config.settings import settings

logger = logging.getLogger(__name__)


class BaseTask:
    async def process_block(self):
        raise NotImplementedError

    async def run(self, interrupt_handler: InterruptHandler) -> None:
        while not interrupt_handler.exit:
            start_time = time.time()
            try:
                await self.process_block()
            except Exception as exc:
                log_verbose(exc)

            block_processing_time = time.time() - start_time
            sleep_time = max(
                float(settings.network_config.SECONDS_PER_BLOCK) - block_processing_time, 0
            )
            await interrupt_handler.sleep(sleep_time)
