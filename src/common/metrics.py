import toml  # type: ignore
from prometheus_client import Gauge, Info, start_http_server

from src.config.settings import METRICS_HOST, METRICS_PORT


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
        app_version = toml.load('pyproject.toml')['tool']['poetry']['version']
        self.app_version.info({'version': app_version})


metrics = Metrics()
metrics.set_app_version()


async def metrics_server() -> None:
    start_http_server(METRICS_PORT, METRICS_HOST)
