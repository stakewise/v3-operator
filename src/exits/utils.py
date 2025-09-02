import asyncio
import dataclasses
import logging
import random

import aiohttp
from aiohttp import ClientError
from eth_typing import ChecksumAddress
from sw_utils.common import urljoin
from sw_utils.decorators import retry_aiohttp_errors
from sw_utils.typings import ProtocolConfig
from web3 import Web3

from src.common.typings import OracleApproval, OraclesApproval
from src.common.utils import format_error, process_oracles_approvals, warning_verbose
from src.config.settings import (
    DEFAULT_RETRY_TIME,
    OUTDATED_SIGNATURES_URL_PATH,
    UPDATE_SIGNATURES_URL_PATH,
)
from src.exits.typings import SignatureRotationRequest

logger = logging.getLogger(__name__)


async def send_signature_rotation_requests(
    protocol_config: ProtocolConfig, request: SignatureRotationRequest
) -> OraclesApproval:
    """Requests exit signature rotation from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = [(oracle.address, oracle.endpoints) for oracle in protocol_config.oracles]
    random.shuffle(endpoints)  # nosec

    approvals: dict[ChecksumAddress, OracleApproval] = {}
    failed_endpoints: list[str] = []
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(
            *[
                send_signature_rotation_request_to_replicas(
                    session=session, replicas=replicas, payload=payload
                )
                for address, replicas in endpoints
            ],
            return_exceptions=True,
        )
        for (address, replicas), result in zip(endpoints, results):
            if isinstance(result, BaseException):
                warning_verbose(
                    'All endpoints for oracle %s failed to sign signature rotation request. '
                    'Last error: %s',
                    address,
                    format_error(result),
                )
                failed_endpoints.extend(replicas)
                continue
            approvals[address] = result

    logger.info(
        'Fetched oracle approvals for signatures update of %d validators. '
        'Received approvals: %d out of %d',
        len(request.public_keys),
        len(approvals),
        len(protocol_config.oracles),
    )

    if failed_endpoints:
        logger.error(
            'The oracles with endpoints %s have failed to respond.', ', '.join(failed_endpoints)
        )

    return process_oracles_approvals(approvals, protocol_config.validators_threshold)


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def send_signature_rotation_request_to_replicas(
    session: aiohttp.ClientSession, replicas: list[str], payload: dict
) -> OracleApproval:
    last_error = None

    # Shuffling may help if the first endpoint is slower than others
    replicas = random.sample(replicas, len(replicas))  # nosec
    for endpoint in replicas:
        try:
            return await send_signature_rotation_request(session, endpoint, payload)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
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
async def get_oracle_outdated_signatures_response(
    oracle_endpoint: str, vault: ChecksumAddress
) -> dict:
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
    path = OUTDATED_SIGNATURES_URL_PATH.format(vault=vault)
    url = urljoin(oracle_endpoint, path)

    async with aiohttp.ClientSession() as session:
        async with session.get(url=url) as response:
            response.raise_for_status()
            data = await response.json()
    return data
