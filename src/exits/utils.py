import asyncio
import dataclasses
import logging
import random
from urllib.parse import urljoin

import aiohttp
from aiohttp import ClientError
from eth_typing import ChecksumAddress
from sw_utils.decorators import retry_aiohttp_errors
from web3 import Web3

from src.common.typings import OracleApproval, Oracles, OraclesApproval
from src.common.utils import format_error, process_oracles_approvals
from src.config.settings import (
    DEFAULT_RETRY_TIME,
    OUTDATED_SIGNATURES_URL_PATH,
    UPDATE_SIGNATURES_URL_PATH,
    settings,
)
from src.exits.typings import SignatureRotationRequest

logger = logging.getLogger(__name__)


async def send_signature_rotation_requests(
    oracles: Oracles, request: SignatureRotationRequest
) -> OraclesApproval:
    """Requests exit signature rotation from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = list(zip(oracles.addresses, oracles.endpoints))
    random.shuffle(endpoints)

    approvals: dict[ChecksumAddress, OracleApproval] = {}
    async with aiohttp.ClientSession() as session:
        for address, replicas in endpoints:
            try:
                response = await send_signature_rotation_request_to_replicas(
                    session=session, replicas=replicas, payload=payload
                )
            except Exception as e:
                if settings.verbose:
                    logger.warning(
                        'All endpoints for oracle %s failed to sign signature rotation request. '
                        'Last error: %s',
                        address,
                        format_error(e),
                    )
                continue
            approvals[address] = response

    return process_oracles_approvals(approvals, oracles.validators_threshold)


# pylint: disable=duplicate-code
@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def send_signature_rotation_request_to_replicas(
    session: aiohttp.ClientSession, replicas: list[str], payload: dict
) -> OracleApproval:
    last_error = None

    # Shuffling may help if the first endpoint is slower than others
    replicas = random.sample(replicas, len(replicas))

    for endpoint in replicas:
        try:
            return await send_signature_rotation_request(session, endpoint, payload)
        except (ClientError, asyncio.TimeoutError) as e:
            if settings.verbose:
                logger.warning('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('Failed to get response from replicas')


async def send_signature_rotation_request(
    session: aiohttp.ClientSession, endpoint: str, payload: dict
) -> OracleApproval:
    """Requests exit signature rotation from single oracle."""
    logger.debug('send_signature_rotation_request to %s', endpoint)

    endpoint = urljoin(endpoint, UPDATE_SIGNATURES_URL_PATH)

    async with session.post(url=endpoint, json=payload) as response:
        response.raise_for_status()
        data = await response.json()

    return OracleApproval(
        ipfs_hash=data['ipfs_hash'],
        signature=Web3.to_bytes(hexstr=data['signature']),
        deadline=data['deadline'],
    )


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def get_oracle_outdated_signatures_response(oracle_endpoint: str) -> dict:
    """
    :param oracle_endpoint:
    :return: Example response
    ```
    {
        "exit_signature_block_number": 100,
        "validators": [{"index": 1}, ...]
    }
    ```
    """
    path = OUTDATED_SIGNATURES_URL_PATH.format(vault=settings.vault)
    url = urljoin(oracle_endpoint, path)

    async with aiohttp.ClientSession() as session:
        async with session.get(url=url) as response:
            response.raise_for_status()
            data = await response.json()
    return data
