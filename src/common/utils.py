import asyncio
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from decimal import ROUND_FLOOR, Decimal, localcontext
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, TypeVar, overload

import click
import tenacity
from eth_typing import BlockNumber, ChecksumAddress
from pythonjsonlogger import jsonlogger
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Timestamp

from src.common.consensus import get_chain_finalized_head
from src.common.exceptions import (
    InvalidOraclesRequestError,
    NotEnoughOracleApprovalsError,
)
from src.common.typings import OracleApproval, OraclesApproval
from src.config.settings import LOG_DATE_FORMAT, settings

logger = logging.getLogger(__name__)

T = TypeVar('T')


def get_build_version() -> str | None:
    path = Path(__file__).parents[1].joinpath('GIT_SHA')
    if not path.exists():
        return None

    with path.open(encoding='utf-8') as fh:
        return fh.read().strip()


def log_verbose(e: Exception) -> None:
    if settings.verbose:
        logger.exception(e)
    else:
        logger.error(format_error(e))


def warning_verbose(msg: str, *args) -> None:  # type: ignore
    if settings.verbose:
        logger.warning(msg, *args)


def format_error(e: BaseException) -> str:
    if isinstance(e, tenacity.RetryError):
        # get original error
        e = e.last_attempt.exception()  # type: ignore

    if isinstance(e, asyncio.TimeoutError):
        # str(e) returns empty string
        return repr(e)

    if isinstance(e, Web3Exception):
        # str(e) gives hex output. Not user-friendly.
        return e.__class__.__name__

    return str(e)


async def is_block_finalized(block_number: BlockNumber) -> bool:
    chain_head = await get_chain_finalized_head()
    return chain_head.block_number >= block_number


def get_current_timestamp() -> Timestamp:
    return Timestamp(int(datetime.now(timezone.utc).timestamp()))


def process_oracles_approvals(
    approvals: dict[ChecksumAddress, OracleApproval], votes_threshold: int
) -> OraclesApproval:
    candidates = defaultdict(list)
    for address, approval in approvals.items():
        candidates[(approval.ipfs_hash, approval.deadline)].append((address, approval.signature))

    if not candidates:
        # all oracles have rejected the request
        raise InvalidOraclesRequestError()

    winner = max(candidates, key=lambda x: len(candidates[x]))
    votes = candidates[winner]
    if len(votes) < votes_threshold:
        # not enough oracles have approved the request
        # Fill `failed_endpoints` later
        raise NotEnoughOracleApprovalsError(num_votes=len(votes), threshold=votes_threshold)

    signatures = b''
    for _, signature in sorted(votes, key=lambda x: Web3.to_int(hexstr=x[0]))[:votes_threshold]:
        signatures += signature
    return OraclesApproval(ipfs_hash=winner[0], signatures=signatures, deadline=winner[1])


@overload
def chunkify(items: list[T], size: int) -> Iterator[list[T]]: ...


@overload
def chunkify(items: range, size: int) -> Iterator[range]: ...


def chunkify(items, size):  # type: ignore[no-untyped-def]
    for i in range(0, len(items), size):
        yield items[i : i + size]


def greenify(value: Any) -> str:
    return click.style(value, bold=True, fg='green')


class JsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):  # type: ignore
        super().add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            date = datetime.fromtimestamp(record.created, tz=timezone.utc)
            log_record['timestamp'] = date.strftime(LOG_DATE_FORMAT)
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname


class RateLimiter:
    def __init__(self, min_interval: int) -> None:
        self.min_interval = min_interval
        self.previous_time: float | None = None

    async def ensure_interval(self) -> None:
        current_time = time.time()

        if self.previous_time is not None:
            elapsed = current_time - self.previous_time
            await asyncio.sleep(self.min_interval - elapsed)

        self.previous_time = current_time


def round_down(d: int | Decimal, precision: int) -> Decimal:
    if isinstance(d, int):
        d = Decimal(d)

    with localcontext() as ctx:
        ctx.rounding = ROUND_FLOOR
        return round(d, precision)


def find_first(iterable: Iterable[T], predicate: Callable[[T], bool]) -> T | None:
    return next((item for item in iterable if predicate(item)), None)
