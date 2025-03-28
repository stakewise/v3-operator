import asyncio
import dataclasses
import logging
import random
from dataclasses import dataclass

from aiohttp import ClientError, ClientSession, ClientTimeout
from eth_typing import ChecksumAddress, HexStr
from sw_utils import ProtocolConfig
from sw_utils.decorators import retry_aiohttp_errors
from web3 import Web3

from src.common.exceptions import NotEnoughOracleConsolidationError
from src.common.utils import RateLimiter, format_error, warning_verbose
from src.config.settings import DEFAULT_RETRY_TIME, ORACLES_CONSOLIDATION_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass
class ConsolidationRequest:
    public_keys: list[tuple[HexStr, HexStr]]
    vault: ChecksumAddress


@dataclass
class OraclesConsolidation:
    signatures: bytes


async def poll_consolidation_approval(
    protocol_config: ProtocolConfig,
    from_to_keys: list[tuple[HexStr, HexStr]],
    vault: ChecksumAddress,
) -> bytes | str:
    """
    Polls oracles for approval of validator consolidation signature
    """
    approvals_min_interval = 1
    rate_limiter = RateLimiter(approvals_min_interval)

    consolidation_request = ConsolidationRequest(
        public_keys=from_to_keys,
        vault=vault,
    )
    while True:
        # Keep min interval between requests
        await rate_limiter.ensure_interval()

        # Send approval requests
        try:
            consolidation_signature = await send_consolidation_requests(
                protocol_config, consolidation_request
            )
            return consolidation_signature
        except NotEnoughOracleConsolidationError as e:
            logger.error(
                'Not enough oracle approvals for validator registration: %d. Threshold is %d.',
                e.num_votes,
                e.threshold,
            )


async def send_consolidation_requests(
    protocol_config: ProtocolConfig, request: ConsolidationRequest
) -> bytes:
    """Requests approval from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = [(oracle.address, oracle.endpoints) for oracle in protocol_config.oracles]

    async with ClientSession(timeout=ClientTimeout(ORACLES_CONSOLIDATION_TIMEOUT)) as session:
        results = await asyncio.gather(
            *[
                send_consolidate_request_to_replicas(
                    session=session, replicas=replicas, payload=payload
                )
                for address, replicas in endpoints
            ],
            return_exceptions=True,
        )

    approvals: dict[ChecksumAddress, bytes] = {}
    failed_endpoints: list[str] = []

    for (address, replicas), result in zip(endpoints, results):
        if isinstance(result, BaseException):
            warning_verbose(
                'All endpoints for oracle %s failed to sign validators approval request. '
                'Last error: %s',
                address,
                format_error(result),
            )
            failed_endpoints.extend(replicas)
            continue

        approvals[address] = result

    logger.info(
        'Fetched oracle approvals for validator consolidation: Received %d out of %d approvals.',
        len(approvals),
        len(protocol_config.oracles),
    )

    if failed_endpoints:
        logger.error(
            'The oracles with endpoints %s have failed to respond.', ', '.join(failed_endpoints)
        )

    # return process_oracles_approvals(approvals, protocol_config.validators_threshold)
    return approvals


# pylint: disable=duplicate-code
@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def send_consolidate_request_to_replicas(
    session: ClientSession, replicas: list[str], payload: dict
) -> OraclesConsolidation:
    last_error = None

    # Shuffling may help if the first endpoint is slower than others
    replicas = random.sample(replicas, len(replicas))

    for endpoint in replicas:
        try:
            return await send_consolidate_request(session, endpoint, payload)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('Failed to get response from replicas')


async def send_consolidate_request(
    session: ClientSession, endpoint: str, payload: dict
) -> OraclesConsolidation:
    """Requests approval from single oracle."""
    logger.debug('send_approval_request to %s', endpoint)
    try:
        async with session.post(url=endpoint, json=payload) as response:
            if response.status == 400:
                logger.warning('%s response: %s', endpoint, await response.json())
            response.raise_for_status()
            data = await response.json()
    except (ClientError, asyncio.TimeoutError) as e:

        raise e
    logger.debug('Received response from oracle %s: %s', endpoint, data)
    return OraclesConsolidation(
        signatures=Web3.to_bytes(hexstr=data['signature']),
    )
