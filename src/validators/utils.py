import asyncio
import dataclasses
import json
import logging
import random
from multiprocessing import Pool
from os import listdir
from os.path import isfile, join
from pathlib import Path

import milagro_bls_binding as bls
from aiohttp import ClientError, ClientSession, ClientTimeout
from eth_typing import ChecksumAddress, HexAddress, HexStr
from eth_utils import add_0x_prefix
from multiproof import StandardMerkleTree
from staking_deposit.key_handling.keystore import ScryptKeystore
from sw_utils import get_eth1_withdrawal_credentials
from sw_utils.decorators import retry_aiohttp_errors
from web3 import Web3

from src.common.contracts import validators_registry_contract
from src.common.typings import OracleApproval, Oracles
from src.config.settings import DEFAULT_RETRY_TIME, ORACLES_VALIDATORS_TIMEOUT, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import (
    KeystoreException,
    RegistryRootChangedError,
    ValidatorIndexChangedError,
)
from src.validators.execution import get_latest_network_validator_public_keys
from src.validators.signing import encode_tx_validator
from src.validators.typings import (
    ApprovalRequest,
    BLSPrivkey,
    DepositData,
    KeystoreFile,
    Keystores,
    Validator,
)

logger = logging.getLogger(__name__)


async def send_approval_requests(oracles: Oracles, request: ApprovalRequest) -> tuple[bytes, str]:
    """Requests approval from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = list(zip(oracles.addresses, oracles.endpoints))

    ipfs_hashes = []
    responses: dict[ChecksumAddress, bytes] = {}
    async with ClientSession(timeout=ClientTimeout(ORACLES_VALIDATORS_TIMEOUT)) as session:
        results = await asyncio.gather(
            *[
                send_approval_request_to_replicas(
                    session=session, replicas=replicas, payload=payload
                )
                for address, replicas in endpoints
            ],
            return_exceptions=True,
        )

    for address, result in zip(oracles.addresses, results):
        if isinstance(result, Exception):
            logger.error(result)
            continue

        ipfs_hashes.append(result.ipfs_hash)
        responses[address] = result.signature

    if not ipfs_hashes:
        raise RuntimeError('No oracles to get approval from')

    if len(ipfs_hashes) < oracles.validators_threshold:
        raise RuntimeError('Not enough oracles to get approval from')

    if len(set(ipfs_hashes)) != 1:
        raise ValueError('Different oracles IPFS hashes for approval request.')

    signatures = b''
    for address in sorted(responses.keys())[: oracles.validators_threshold]:
        signatures += responses[address]
    return signatures, ipfs_hashes[0]


# pylint: disable=duplicate-code
@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def send_approval_request_to_replicas(
    session: ClientSession, replicas: list[str], payload: dict
) -> OracleApproval:
    last_error = None

    # Shuffling may help if the first endpoint is slower than others
    replicas = random.sample(replicas, len(replicas))

    for endpoint in replicas:
        try:
            return await send_approval_request(session, endpoint, payload)
        except (ClientError, asyncio.TimeoutError) as e:
            logger.debug('%s for %s', repr(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('Failed to get response from replicas')


async def send_approval_request(
    session: ClientSession, endpoint: str, payload: dict
) -> OracleApproval:
    """Requests approval from single oracle."""
    logger.debug('send_approval_request to %s', endpoint)
    try:
        async with session.post(url=endpoint, json=payload) as response:
            response.raise_for_status()
            data = await response.json()
    except (ClientError, asyncio.TimeoutError) as e:
        registry_root = await validators_registry_contract.get_registry_root()
        if Web3.to_hex(registry_root) != payload['validators_root']:
            raise RegistryRootChangedError from e

        latest_public_keys = await get_latest_network_validator_public_keys()
        validator_index = NetworkValidatorCrud().get_next_validator_index(list(latest_public_keys))
        if validator_index != payload['validator_index']:
            raise ValidatorIndexChangedError from e

        raise e
    logger.debug('Received response from oracle %s: %s', endpoint, response)
    return OracleApproval(
        ipfs_hash=data['ipfs_hash'],
        signature=Web3.to_bytes(hexstr=data['signature']),
    )


def list_keystore_files() -> list[KeystoreFile]:
    keystores_dir = settings.keystores_dir
    keystores_password_dir = settings.keystores_password_dir
    keystores_password_file = settings.keystores_password_file

    res: list[KeystoreFile] = []
    for f in listdir(keystores_dir):
        if not (isfile(keystores_dir / f) and f.startswith('keystore') and f.endswith('.json')):
            continue

        password_file = keystores_password_dir / f.replace('.json', '.txt')
        if not isfile(password_file):
            password_file = keystores_password_file

        password = _load_keystores_password(password_file)
        res.append(KeystoreFile(name=f, password=password))

    return res


def load_keystores() -> Keystores | None:
    """Extracts private keys from the keystores."""

    keystore_files = list_keystore_files()
    logger.info('Loading keystores from %s...', settings.keystores_dir)
    with Pool(processes=settings.load_keystores_concurrency) as pool:
        # pylint: disable-next=unused-argument
        def _stop_pool(*args, **kwargs):
            pool.close()

        results = [
            pool.apply_async(
                _process_keystore_file,
                (keystore_file, settings.keystores_dir),
                error_callback=_stop_pool,
            )
            for keystore_file in keystore_files
        ]
        keys = []
        for result in results:
            result.wait()
            try:
                keys.append(result.get())
            except KeystoreException as e:
                logger.error(e)
                return None

        existing_keys: list[tuple[HexStr, BLSPrivkey]] = [key for key in keys if key]
        keystores = Keystores(dict(existing_keys))

    logger.info('Loaded %d keystores', len(keystores))
    return keystores


def load_deposit_data(vault: HexAddress, deposit_data_file: Path) -> DepositData:
    """Loads and verifies deposit data."""
    with open(deposit_data_file, 'r', encoding='utf-8') as f:
        deposit_data = json.load(f)

    credentials = get_eth1_withdrawal_credentials(vault)
    leaves: list[tuple[bytes, int]] = []
    validators: list[Validator] = []
    for i, data in enumerate(deposit_data):
        validator = Validator(
            deposit_data_index=i,
            public_key=add_0x_prefix(data['pubkey']),
            signature=add_0x_prefix(data['signature']),
        )
        leaves.append((encode_tx_validator(credentials, validator), i))
        validators.append(validator)

    tree = StandardMerkleTree.of(leaves, ['bytes', 'uint256'])

    return DepositData(validators=validators, tree=tree)


def _process_keystore_file(
    keystore_file: KeystoreFile, keystore_path: Path
) -> tuple[HexStr, BLSPrivkey] | None:
    file_name = keystore_file.name
    keystores_password = keystore_file.password
    file_path = join(keystore_path, file_name)

    try:
        keystore = ScryptKeystore.from_file(file_path)
    except BaseException as e:
        raise KeystoreException(f'Invalid keystore format in file "{file_name}"') from e

    try:
        private_key = BLSPrivkey(keystore.decrypt(keystores_password))
    except BaseException as e:
        raise KeystoreException(f'Invalid password for keystore "{file_name}"') from e
    public_key = Web3.to_hex(bls.SkToPk(private_key))
    return public_key, private_key


def _load_keystores_password(password_path: Path) -> str:
    with open(password_path, 'r', encoding='utf-8') as f:
        return f.read().strip()
