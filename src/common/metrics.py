from prometheus_client import Gauge, Info, start_http_server

import src
from src.config.settings import settings
from src.utils import get_build_version


class Metrics:
    def __init__(self):
        self.app_version = Info('app_version', 'V3 Operator version')
        self.build_version = Info('build_version', 'V3 Operator version')
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

    def set_build_version(self):
        self.build_version.info({'version': get_build_version()})


metrics = Metrics()
metrics.set_app_version()
metrics.set_build_version()


async def metrics_server() -> None:
    start_http_server(settings.METRICS_PORT, settings.METRICS_HOST)
