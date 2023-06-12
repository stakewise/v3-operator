import toml
from prometheus_client import start_http_server, Gauge, Info
from src.config.settings import METRICS_HOST, METRICS_PORT


app_version = toml.load("pyproject.toml")["tool"]["poetry"]["version"]

APP_VERSION: Info = Info('app_version', 'V3 Operator version')
APP_VERSION.info({'version': app_version})
BLOCK_NUMBER: Gauge = Gauge('block_number', 'Current block number')
SLOT_NUMBER: Gauge = Gauge('slot_number', 'Current slot number')
WALLET_INFO: Gauge = Gauge('wallet_info', 'Wallet info', labelnames=['balance','min_balance'])
NETWORK_VALIDATORS_COUNT: Gauge = Gauge('network_validators_count', 'Current amount of validators in network')
LAST_VOTES_TIME: Gauge = Gauge('last_votes_time', 'Last votes time')
VAULT_BALANCE: Gauge = Gauge('vault_balance', 'Current vault balance')

async def metrics_server() -> None:
    start_http_server(METRICS_PORT, METRICS_HOST)
