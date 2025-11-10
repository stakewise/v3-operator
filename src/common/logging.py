import logging
import warnings
from urllib.parse import urlparse

from src.common.utils import JsonFormatter
from src.config.settings import (
    LOG_DATE_FORMAT,
    LOG_JSON,
    LOG_WHITELISTED_DOMAINS,
    settings,
)

LOG_LEVELS = [
    'FATAL',
    'ERROR',
    'WARNING',
    'INFO',
    'DEBUG',
]


class TokenPlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return hide_tokens(super().format(record))


class TokenJsonFormatter(JsonFormatter):
    def format(self, record: logging.LogRecord) -> str:
        return hide_tokens(super().format(record))


def setup_logging() -> None:
    formatter: TokenJsonFormatter | TokenPlainFormatter
    if settings.log_format == LOG_JSON:
        formatter = TokenJsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
        logHandler = logging.StreamHandler()
        logHandler.setFormatter(formatter)
        logging.basicConfig(
            level=settings.log_level,
            handlers=[logHandler],
        )
    else:
        formatter = TokenPlainFormatter()
        logHandler = logging.StreamHandler()
        logHandler.setFormatter(formatter)
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt=LOG_DATE_FORMAT,
            level=settings.log_level,
            handlers=[logHandler],
        )
    if not settings.verbose:
        logging.getLogger('sw_utils.execution').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.consensus').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.ipfs').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.decorators').setLevel(logging.ERROR)

        # Logging config does not affect messages issued by `warnings` module
        warnings.simplefilter('ignore')

    logging.getLogger('web3').setLevel(settings.web3_log_level)
    logging.getLogger('gql.transport.aiohttp').setLevel(settings.gql_log_level)


def hide_tokens(msg: str) -> str:
    endpoints = settings.execution_endpoints + settings.consensus_endpoints
    for endpoint in endpoints:
        if any(e in endpoint for e in LOG_WHITELISTED_DOMAINS):
            continue
        if endpoint in msg:
            parsed_endpoint = urlparse(endpoint)
            scheme = parsed_endpoint.scheme or ''
            if scheme:
                scheme += '://'
            hostname = parsed_endpoint.hostname or ''
            msg = msg.replace(
                endpoint,
                scheme + hostname + '/<hidden>',
            )
    return msg
