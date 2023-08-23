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

from src.common.typings import OracleApproval, Oracles
from src.config.settings import DEFAULT_RETRY_TIME, UPDATE_SIGNATURES_URL_PATH
from src.exits.typings import SignatureRotationRequest

logger = logging.getLogger(__name__)


async def send_signature_rotation_requests(
    oracles: Oracles, request: SignatureRotationRequest
) -> tuple[bytes, str]:
    """Requests exit signature rotation from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = list(zip(oracles.addresses, oracles.endpoints))
    random.shuffle(endpoints)

    ipfs_hash = None
    responses: dict[ChecksumAddress, bytes] = {}
    async with aiohttp.ClientSession() as session:
        for address, replicas in endpoints:
            response = await send_signature_rotation_request_to_replicas(session, replicas, payload)
            if ipfs_hash is None:
                ipfs_hash = response.ipfs_hash
            elif ipfs_hash != response.ipfs_hash:
                raise ValueError('Different oracles ipfs hashes for signature rotation request')

            responses[address] = response.signature

    if ipfs_hash is None:
        raise RuntimeError('No oracles to get signature rotation from')

    signatures = b''
    for address in sorted(responses.keys()):
        signatures += responses[address]

    return signatures, ipfs_hash


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
            logger.debug('%s for %s', repr(e), endpoint)
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
        ipfs_hash=data['ipfs_hash'], signature=Web3.to_bytes(hexstr=data['signature'])
    )
