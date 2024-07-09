import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import click
import tenacity
from eth_typing import BlockNumber, ChecksumAddress
from pythonjsonlogger import jsonlogger
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Timestamp

from src.common.clients import consensus_client, execution_client
from src.common.exceptions import (
    InvalidOraclesRequestError,
    NotEnoughOracleApprovalsError,
)
from src.common.typings import OracleApproval, OraclesApproval
from src.config.settings import LOG_DATE_FORMAT, settings

logger = logging.getLogger(__name__)


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


def format_error(e: Exception) -> str:
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
    chain_head = await consensus_client.get_chain_finalized_head(
        settings.network_config.SLOTS_PER_EPOCH
    )
    return chain_head.execution_block >= block_number


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


def chunkify(items, size):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def greenify(value):
    return click.style(value, bold=True, fg='green')


def calc_slot_by_block_timestamp(ts: Timestamp) -> int:
    return int(
        (ts - settings.network_config.GENESIS_TIMESTAMP) / settings.network_config.SECONDS_PER_BLOCK
    )


async def calc_slot_by_block_number(block_number: BlockNumber) -> int:
    execution_block = await execution_client.eth.get_block(block_number)
    return calc_slot_by_block_timestamp(execution_block['timestamp'])


class JsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        if not log_record.get('timestamp'):
            date = datetime.fromtimestamp(record.created, tz=timezone.utc)
            log_record['timestamp'] = date.strftime(LOG_DATE_FORMAT)
        if log_record.get('level'):
            log_record['level'] = log_record['level'].upper()
        else:
            log_record['level'] = record.levelname
