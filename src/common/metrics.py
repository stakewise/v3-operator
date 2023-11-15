from prometheus_client import Gauge, Info, start_http_server

import src
from src.common.clients import execution_client
from src.common.consensus import get_chain_finalized_head
from src.common.tasks import BaseTask
from src.config.settings import settings


# pylint: disable-next=too-few-public-methods
class Metrics:
    def __init__(self):
        self.app_version = Info('app_version', 'V3 Operator version')
        self.block_number = Gauge('block_number', 'Current block number')
        self.slot_number = Gauge('slot_number', 'Current slot number')
        self.wallet_balance = Gauge('wallet_balance', 'Current wallet balance')
        self.outdated_signatures = Gauge('outdated_signatures', 'The number of outdated signatures')
        self.stakeable_assets = Gauge('stakeable_assets', 'The amount of stakeable assets')
        self.unused_validator_keys = Gauge(
            'unused_validator_keys', 'The number of unused validator keys in deposit data file'
        )

    def set_app_version(self):
        self.app_version.info({'version': src.__version__})


metrics = Metrics()
metrics.set_app_version()


async def metrics_server() -> None:
    start_http_server(settings.metrics_port, settings.metrics_host)


class MetricsTask(BaseTask):
    async def process(self) -> None:
        chain_state = await get_chain_finalized_head()
        metrics.block_number.set(await execution_client.eth.get_block_number())
        metrics.slot_number.set(chain_state.consensus_block)
