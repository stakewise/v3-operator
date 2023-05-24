import logging
from pathlib import Path

from src.config.settings import VERBOSE

logger = logging.getLogger(__name__)


def get_build_version() -> str | None:
    path = Path(__file__).parents[1].joinpath('GIT_SHA')
    if not path.exists():
        return None

    with path.open() as fh:
        return fh.read().strip()


def log_verbose(e: Exception):
    if VERBOSE:
        logger.exception(e)
    else:
        logger.error(e)
