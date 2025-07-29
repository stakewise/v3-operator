from __future__ import annotations

import time
from types import TracebackType
from typing import Any, Literal

from src.nodes.exceptions import NodeException


class Timeout(Exception):
    """
    A limited subset of the `gevent.Timeout` context manager.
    """

    seconds = None
    exception = None
    begun_at = None
    is_running = None

    def __init__(
        self,
        seconds: int | None = None,
        exception: Any | None = None,
    ):
        self.seconds = seconds
        self.exception = exception

    def __str__(self) -> str:
        if self.seconds is None:
            return ''
        return f"{self.seconds} seconds"

    def __enter__(self) -> Timeout:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        return False

    @property
    def expire_at(self) -> float:
        if self.seconds is None:
            raise NodeException('Timeouts with `seconds == None` do not have an expiration time')
        if self.begun_at is None:
            raise NodeException('Timeout has not been started')
        return self.begun_at + self.seconds

    def start(self) -> None:
        if self.is_running is not None:
            raise NodeException('Timeout has already been started')
        self.begun_at = time.time()
        self.is_running = True

    def check(self) -> None:
        if self.is_running is None:
            raise NodeException('Timeout has not been started')
        if self.is_running is False:
            raise NodeException('Timeout has already been cancelled')
        if self.seconds is None:
            return
        if time.time() > self.expire_at:
            self.is_running = False
            if isinstance(self.exception, type):
                raise self.exception(str(self))
            if isinstance(self.exception, Exception):
                raise self.exception
            raise self

    def cancel(self) -> None:
        self.is_running = False
