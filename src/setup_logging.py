import logging

from src.config.settings import settings


def setup_logging() -> None:
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=settings.LOG_LEVEL,
    )
