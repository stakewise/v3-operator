import logging
import warnings

from src.common.utils import JsonFormatter
from src.config.settings import LOG_DATE_FORMAT, LOG_JSON, settings

LOG_LEVELS = [
    'FATAL',
    'ERROR',
    'WARNING',
    'INFO',
    'DEBUG',
]


def setup_logging() -> None:
    handler: logging.Handler

    if settings.enable_file_logging and settings.log_file_path is not None:
        handler = logging.FileHandler(settings.log_file_path)
    else:
        handler = logging.StreamHandler()

    if settings.log_format == LOG_JSON:
        formatter = JsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
        handler.setFormatter(formatter)
        logging.basicConfig(
            level=settings.log_level,
            handlers=[handler],
        )
    else:
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt=LOG_DATE_FORMAT,
            level=settings.log_level,
            handlers=[handler],
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
