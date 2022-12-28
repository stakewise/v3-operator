import dataclasses
import logging
import random
from os import listdir
from os.path import isfile, join

import aiohttp
import backoff
import milagro_bls_binding as bls
from eth_typing import ChecksumAddress, HexStr
from staking_deposit.key_handling.keystore import ScryptKeystore
from web3 import Web3

from src.config.settings import KEYSTORES_PASSWORD, KEYSTORES_PATH
from src.validators.typings import ApprovalRequest, BLSPrivkey, OracleApproval, Oracles

logger = logging.getLogger(__name__)


async def send_approval_requests(oracles: Oracles, request: ApprovalRequest) -> tuple[bytes, str]:
    """Requests approval from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = list(zip(oracles.addresses, oracles.endpoints))
    random.shuffle(endpoints)

    ipfs_hash = None
    responses: dict[ChecksumAddress, bytes] = {}
    async with aiohttp.ClientSession() as session:
        for address, endpoint in endpoints:
            response = await send_approval_request(session, endpoint, payload)
            if ipfs_hash is None:
                ipfs_hash = response.ipfs_hash
            elif ipfs_hash != response.ipfs_hash:
                raise ValueError('Different oracles ipfs hashes for approval request')

            responses[address] = response.signature

    if ipfs_hash is None:
        raise RuntimeError('No oracles to get approval from')

    signatures = b''
    for address in sorted(responses.keys()):
        signatures += responses[address]

    return signatures, ipfs_hash


@backoff.on_exception(backoff.expo, Exception, max_time=60)
async def send_approval_request(
    session: aiohttp.ClientSession,
    endpoint: str,
    payload: dict
) -> OracleApproval:
    """Requests approval from single oracle."""
    response = await session.post(url=endpoint, json=payload)
    response.raise_for_status()
    data = await response.json()
    return OracleApproval(
        ipfs_hash=data['ipfs_hash'],
        signature=Web3.to_bytes(hexstr=data['signature'])
    )


def load_private_keys() -> dict[HexStr, BLSPrivkey]:
    """Extracts private keys from the keystores."""
    private_keys: dict[HexStr, BLSPrivkey] = {}
    for file_name in listdir(KEYSTORES_PATH):
        file_path = join(KEYSTORES_PATH, file_name)
        if not (isfile(file_path) and file_name.startswith('keystore')):
            continue

        keystore = ScryptKeystore.from_file(file_path)
        private_key = BLSPrivkey(keystore.decrypt(KEYSTORES_PASSWORD))
        private_keys[Web3.to_hex(bls.SkToPk(private_key))] = private_key

    logger.info('Loaded %d keystores', len(private_keys))

    return private_keys
