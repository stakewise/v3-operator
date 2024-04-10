import logging
from typing import cast

from prometheus_client import Gauge, Info, start_http_server
from sw_utils import InterruptHandler

import src
from src.common.clients import execution_client
from src.common.consensus import get_chain_finalized_head
from src.common.tasks import BaseTask
from src.config.settings import settings


# pylint: disable-next=too-few-public-methods
class Metrics:
    def __init__(self):
        self.app_version = Info(
            'app_version', 'V3 Operator version', namespace=settings.metrics_prefix
        )
        self.block_number = Gauge(
            'block_number', 'Current block number', namespace=settings.metrics_prefix
        )
        self.slot_number = Gauge(
            'slot_number', 'Current slot number', namespace=settings.metrics_prefix
        )
        self.wallet_balance = Gauge(
            'wallet_balance', 'Current wallet balance', namespace=settings.metrics_prefix
        )
        self.outdated_signatures = Gauge(
            'outdated_signatures',
            'The number of outdated signatures',
            namespace=settings.metrics_prefix,
        )
        self.stakeable_assets = Gauge(
            'stakeable_assets', 'The amount of stakeable assets', namespace=settings.metrics_prefix
        )
        self.unused_validator_keys = Gauge(
            'unused_validator_keys',
            'The number of unused validator keys in deposit data file',
            namespace=settings.metrics_prefix,
        )

    def set_app_version(self):
        self.app_version.info({'version': src.__version__})


# pylint: disable-next=too-few-public-methods
class LazyMetrics:
    def __init__(self):
        self._metrics: Metrics | None = None

    def __getattr__(self, item):
        if self._metrics is None:
            self._metrics = Metrics()
        return getattr(self._metrics, item)


metrics = cast(Metrics, LazyMetrics())

logger = logging.getLogger(__name__)


async def metrics_server() -> None:
    logger.info('Starting metrics server')
    start_http_server(settings.metrics_port, settings.metrics_host)


class MetricsTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        metrics.set_app_version()

        chain_state = await get_chain_finalized_head()
        metrics.block_number.set(await execution_client.eth.get_block_number())
        metrics.slot_number.set(chain_state.consensus_block)
