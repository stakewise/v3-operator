import asyncio
import logging
import time

from src.common.utils import log_verbose
from src.config.settings import settings

logger = logging.getLogger(__name__)


class BaseTask:
    async def process(self):
        raise NotImplementedError

    async def run(self):
        while True:
            start_time = time.time()
            try:
                await self.process()
            except Exception as exc:
                log_verbose(exc)

            block_processing_time = time.time() - start_time
            sleep_time = max(
                float(settings.network_config.SECONDS_PER_BLOCK) - block_processing_time, 0
            )
            await asyncio.sleep(sleep_time)
