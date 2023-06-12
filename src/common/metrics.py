import toml  # type: ignore
from prometheus_client import Gauge, Info, start_http_server

from src.config.settings import METRICS_HOST, METRICS_PORT


class Metrics:
    def __init__(self):
        self.app_version = Info('app_version', 'V3 Operator version')
        self.block_number = Gauge('block_number', 'Current block number')
        self.slot_number = Gauge('slot_number', 'Current slot number')
        self.last_votes_time = Gauge('last_votes_time', 'Last votes time')
        self.operator_balance = Gauge('operator_balance', 'Current operator balance')
        self.available_validators = Gauge(
            'available_validators', 'Amount of validators available for registration'
        )

    def set_app_version(self):
        app_version = toml.load('pyproject.toml')['tool']['poetry']['version']
        self.app_version.info({'version': app_version})


metrics = Metrics()
metrics.set_app_version()


async def metrics_server() -> None:
    start_http_server(METRICS_PORT, METRICS_HOST)
