import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import tenacity
from eth_typing import BlockNumber, ChecksumAddress
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Timestamp, Wei

from src.common.clients import consensus_client
from src.common.exceptions import (
    InvalidOraclesRequestError,
    NotEnoughOracleApprovalsError,
)
from src.common.typings import OracleApproval, OraclesApproval
from src.config.settings import settings

logger = logging.getLogger(__name__)

WAD = Web3.to_wei(1, 'ether')
MGNO_RATE = Web3.to_wei(32, 'ether')


def convert_to_gno(mgno_amount: Wei) -> Wei:
    """Converts mGNO to GNO."""
    return Wei(mgno_amount * WAD // MGNO_RATE)


def get_build_version() -> str | None:
    path = Path(__file__).parents[1].joinpath('GIT_SHA')
    if not path.exists():
        return None

    with path.open(encoding='utf-8') as fh:
        return fh.read().strip()


def log_verbose(e: Exception):
    if settings.verbose:
        logger.exception(e)
    else:
        if isinstance(e, tenacity.RetryError):
            # get original error
            e = e.last_attempt.exception()  # type: ignore

        logger.error(format_error(e))


def warning_verbose(msg: str, *args: Any) -> None:
    if settings.verbose:
        logger.warning(msg, *args)


def format_error(e: Exception) -> str:
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
        raise NotEnoughOracleApprovalsError(
            num_votes=len(votes), threshold=votes_threshold, failed_endpoints=[]
        )

    signatures = b''
    for _, signature in sorted(votes, key=lambda x: Web3.to_int(hexstr=x[0]))[:votes_threshold]:
        signatures += signature
    return OraclesApproval(ipfs_hash=winner[0], signatures=signatures, deadline=winner[1])
