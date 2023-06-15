import dataclasses
import logging
import random
from urllib.parse import urljoin

import aiohttp
from eth_typing import ChecksumAddress
from sw_utils.decorators import backoff_aiohttp_errors
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import DEFAULT_RETRY_TIME, UPDATE_SIGNATURES_URL_PATH
from src.exits.typings import OracleApproval, SignatureRotationRequest

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
        for address, oracle_endpoint in endpoints:
            endpoint = urljoin(oracle_endpoint, UPDATE_SIGNATURES_URL_PATH)
            response = await send_signature_rotation_request(session, endpoint, payload)
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


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def send_signature_rotation_request(
    session: aiohttp.ClientSession, endpoint: str, payload: dict
) -> OracleApproval:
    """Requests exit signature rotation from single oracle."""
    async with session.post(url=endpoint, json=payload) as response:
        response.raise_for_status()
        data = await response.json()

    return OracleApproval(
        ipfs_hash=data['ipfs_hash'], signature=Web3.to_bytes(hexstr=data['signature'])
    )
