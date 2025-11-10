import logging
import warnings
from functools import lru_cache
from urllib.parse import urlparse, urlunparse

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
    endpoint_to_hidden_endpoint = _create_hidden_endpoints()
    for endpoint, hidden_endpoint in endpoint_to_hidden_endpoint.items():
        if endpoint in msg:
            msg = msg.replace(endpoint, hidden_endpoint)
    return msg


@lru_cache(maxsize=1)
def _create_hidden_endpoints() -> dict[str, str]:
    results = {}
    endpoints = settings.execution_endpoints + settings.consensus_endpoints
    for endpoint in endpoints:
        if any(e in endpoint for e in LOG_WHITELISTED_DOMAINS):
            continue
        parsed_endpoint = urlparse(endpoint)
        # Reconstruct the URL with the token hidden
        hidden_endpoint = urlunparse(
            (
                parsed_endpoint.scheme,
                parsed_endpoint.hostname,  # Only keep the hostname
                '<hidden>',  # Replace the path with '<hidden>'
                '',
                '',
                '',  # Clear params, query, and fragment
            )
        )
        results[endpoint] = hidden_endpoint
    return results
