import asyncio
from typing import Any, Callable, Optional

from gql.transport.exceptions import TransportError
from sw_utils.decorators import default_log_before
from tenacity import retry, retry_if_exception_type, stop_after_delay, wait_exponential

from src.config.settings import DEFAULT_RETRY_TIME


def retry_gql_errors(
    delay: int = DEFAULT_RETRY_TIME, before: Optional[Callable] = None
) -> Any:
    return retry(
        retry=retry_if_exception_type((TransportError, asyncio.TimeoutError)),
        wait=wait_exponential(multiplier=1, min=1, max=delay // 2),
        stop=stop_after_delay(delay),
        before=before or default_log_before,
    )
