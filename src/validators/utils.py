import dataclasses
import logging
import random
from multiprocessing import Pool
from os import listdir
from os.path import isfile, join

import aiohttp
import backoff
import milagro_bls_binding as bls
from eth_typing import ChecksumAddress, HexStr
from staking_deposit.key_handling.keystore import ScryptKeystore
from tqdm import tqdm
from web3 import Web3

from src.config.settings import KEYSTORES_PASSWORD, KEYSTORES_PATH
from src.validators.typings import ApprovalRequest, BLSPrivkey, OracleApproval, Oracles

logger = logging.getLogger(__name__)


class KeystoreException(Exception):
    ...


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
    async with session.post(url=endpoint, json=payload) as response:
        response.raise_for_status()
        data = await response.json()

    return OracleApproval(
        ipfs_hash=data['ipfs_hash'],
        signature=Web3.to_bytes(hexstr=data['signature'])
    )


def load_private_keys() -> dict[HexStr, BLSPrivkey]:
    """Extracts private keys from the keystores."""
    files = listdir(KEYSTORES_PATH)

    with tqdm(total=len(files)) as pbar, Pool() as pool:

        # pylint: disable-next=unused-argument
        def _stop_pool(*args, **kwargs):
            pool.terminate()

        results = [
            pool.apply_async(
                _process_keystore_file,
                [file],
                callback=lambda x: pbar.update(1),
                error_callback=_stop_pool,
            )
            for file in files
        ]
        keys = []
        for result in results:
            result.wait()
            try:
                keys.append(result.get())
            except KeystoreException as e:
                logger.error(e)
                break

        existing_keys: list[tuple[HexStr, BLSPrivkey]] = [key for key in keys if key]
        private_keys = dict(existing_keys)

    logger.info('Loaded %d keystores', len(private_keys))
    return private_keys


def _process_keystore_file(file_name: str) -> tuple[HexStr, BLSPrivkey] | None:
    file_path = join(KEYSTORES_PATH, file_name)
    if not (isfile(file_path) and file_name.startswith('keystore')):
        return None

    try:
        keystore = ScryptKeystore.from_file(file_path)
    except BaseException as e:
        raise KeystoreException(f'Invalid keystore format in file "{file_name}"') from e

    try:
        private_key = BLSPrivkey(keystore.decrypt(KEYSTORES_PASSWORD))
    except BaseException as e:
        raise KeystoreException(f'Invalid password for keystore "{file_name}"') from e
    public_key = Web3.to_hex(bls.SkToPk(private_key))
    return public_key, private_key
