import asyncio
import logging
import random

from aiohttp import ClientError, ClientSession, ClientTimeout
from sw_utils.common import urljoin
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import Wei

from src.common.utils import format_error, warning_verbose
from src.config.settings import ORACLES_VALIDATORS_TIMEOUT
from src.node_manager.typings import EligibleOperator

logger = logging.getLogger(__name__)

ELIGIBLE_OPERATORS_PATH = '/nodes-manager/eligible-operators'


async def poll_eligible_operators(
    protocol_config: ProtocolConfig,
) -> list[EligibleOperator]:
    """Poll a random oracle for the list of eligible operators."""
    oracles = list(protocol_config.oracles)
    random.shuffle(oracles)  # nosec

    async with ClientSession(timeout=ClientTimeout(ORACLES_VALIDATORS_TIMEOUT)) as session:
        for oracle in oracles:
            try:
                return await _fetch_eligible_from_replicas(
                    session=session, replicas=oracle.endpoints
                )
            except (ClientError, asyncio.TimeoutError, RuntimeError) as e:
                warning_verbose(
                    'Oracle %s failed to return eligible operators: %s',
                    oracle.address,
                    format_error(e),
                )

    logger.error('All oracle endpoints failed to return eligible operators.')
    return []


async def _fetch_eligible_from_replicas(
    session: ClientSession,
    replicas: list[str],
) -> list[EligibleOperator]:
    """Try replicas in random order, return first success."""
    last_error: BaseException | None = None
    replicas = random.sample(replicas, len(replicas))  # nosec

    for endpoint in replicas:
        try:
            return await _fetch_eligible_operators(session, endpoint)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('No replicas available')


async def _fetch_eligible_operators(
    session: ClientSession,
    endpoint: str,
) -> list[EligibleOperator]:
    """Fetch eligible operators from a single oracle endpoint."""
    url = urljoin(endpoint, ELIGIBLE_OPERATORS_PATH)
    logger.debug('Fetching eligible operators from %s', url)

    async with session.get(url=url) as response:
        if response.status == 400:
            logger.warning('%s response: %s', url, await response.json())
        response.raise_for_status()
        data: list[dict] = await response.json()

    return [
        EligibleOperator(
            address=Web3.to_checksum_address(item['address']),
            amount=Wei(item['amount']),
        )
        for item in data
    ]
