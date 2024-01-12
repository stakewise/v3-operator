import logging
import warnings

from src.config.settings import settings


def setup_logging():
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=settings.log_level,
    )
    if not settings.verbose:
        logging.getLogger('sw_utils.execution').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.consensus').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.ipfs').setLevel(logging.ERROR)
        logging.getLogger('sw_utils.decorators').setLevel(logging.ERROR)

        # Logging config does not affect messages issued by `warnings` module
        warnings.simplefilter('ignore')
