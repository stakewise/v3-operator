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


def setup_logging():
    if settings.log_format == LOG_JSON:
        formatter = JsonFormatter('%(timestamp)s %(level)s %(name)s %(message)s')
        logHandler = logging.StreamHandler()
        logHandler.setFormatter(formatter)
        logging.basicConfig(
            level=settings.log_level,
            handlers=[logHandler],
        )
    else:
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt=LOG_DATE_FORMAT,
            level=settings.log_level,
        )
    if not settings.verbose:
        logging.getLogger('sw_utils.execution').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.consensus').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.ipfs').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.decorators').setLevel(logging.ERROR)

        # Logging config does not affect messages issued by `warnings` module
        warnings.simplefilter('ignore')

    logging.getLogger('web3').setLevel(settings.web3_log_level)
