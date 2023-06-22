import asyncio
import dataclasses
import json
import logging
from multiprocessing import Pool
from os import listdir
from os.path import isfile, join
from pathlib import Path

import aiohttp
import milagro_bls_binding as bls
from aiohttp import ClientError
from eth_typing import ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from multiproof import StandardMerkleTree
from staking_deposit.key_handling.keystore import ScryptKeystore
from sw_utils import get_eth1_withdrawal_credentials
from sw_utils.consensus import EXITED_STATUSES
from sw_utils.decorators import backoff_aiohttp_errors
from web3 import Web3

from src.common.clients import consensus_client
from src.common.typings import Oracles
from src.config.settings import DEFAULT_RETRY_TIME, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import (
    KeystoreException,
    RegistryRootChangedError,
    ValidatorIndexChangedError,
)
from src.validators.execution import (
    _encode_tx_validator,
    check_deposit_data_root,
    get_latest_network_validator_public_keys,
    get_validators_registry_root,
)
from src.validators.typings import (
    ApprovalRequest,
    BLSPrivkey,
    DepositData,
    KeystoreFile,
    Keystores,
    OracleApproval,
    Validator,
)

logger = logging.getLogger(__name__)


async def send_approval_requests(oracles: Oracles, request: ApprovalRequest) -> tuple[bytes, str]:
    """Requests approval from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = list(zip(oracles.addresses, oracles.endpoints))

    ipfs_hashes = []
    responses: dict[ChecksumAddress, bytes] = {}
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(
            *[
                send_approval_request(
                    session=session, address=address, endpoint=endpoint, payload=payload
                )
                for address, endpoint in endpoints
            ],
        )

        for result in results:
            ipfs_hashes.append(result.ipfs_hash)
            responses[result.address] = result.signature

        if not ipfs_hashes:
            raise RuntimeError('No oracles to get approval from')

        if ipfs_hashes.count(ipfs_hashes[0]) != len(ipfs_hashes):
            raise ValueError('Different oracles IPFS hashes for approval request')
    signatures = b''
    for address in sorted(responses.keys()):
        signatures += responses[address]
    return signatures, ipfs_hashes[0]


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def send_approval_request(
    session: aiohttp.ClientSession, address: ChecksumAddress, endpoint: str, payload: dict
) -> OracleApproval:
    """Requests approval from single oracle."""
    try:
        async with session.post(url=endpoint, json=payload) as response:
            response.raise_for_status()
            data = await response.json()
    except ClientError as e:
        registry_root = await get_validators_registry_root()
        if Web3.to_hex(registry_root) != payload['validators_root']:
            raise RegistryRootChangedError from e

        latest_public_keys = await get_latest_network_validator_public_keys()
        validator_index = NetworkValidatorCrud().get_next_validator_index(list(latest_public_keys))
        if validator_index != payload['validator_index']:
            raise ValidatorIndexChangedError from e

        raise e
    logger.debug('Received response from oracle %s: %s', endpoint, response)
    return OracleApproval(
        address=address,
        ipfs_hash=data['ipfs_hash'],
        signature=Web3.to_bytes(hexstr=data['signature']),
    )


def list_keystore_files() -> list[KeystoreFile]:
    KEYSTORES_PATH = settings.KEYSTORES_PATH
    KEYSTORES_PASSWORD_FILE = settings.KEYSTORES_PASSWORD_FILE
    KEYSTORES_PASSWORD_DIR = settings.KEYSTORES_PASSWORD_DIR
    key_files = [
        f
        for f in listdir(KEYSTORES_PATH)
        if isfile(join(KEYSTORES_PATH, f)) and f.startswith('keystore') and f.endswith('.json')
    ]

    if KEYSTORES_PASSWORD_DIR:
        # Each key file has its own password
        res: list[KeystoreFile] = []

        for key_file in key_files:
            password_file = key_file.replace('.json', '.txt')
            path = Path(KEYSTORES_PASSWORD_DIR) / password_file
            password = _load_keystores_password(path)
            res.append(KeystoreFile(name=key_file, password=password))

        return res

    if KEYSTORES_PASSWORD_FILE:
        # Common password for all key files
        password = _load_keystores_password(KEYSTORES_PASSWORD_FILE)
        return [KeystoreFile(name=name, password=password) for name in key_files]

    return []


def load_keystores() -> Keystores | None:
    """Extracts private keys from the keystores."""

    keystore_files = list_keystore_files()
    logger.info('Loading keystores from %s...', settings.KEYSTORES_PATH)
    with Pool() as pool:
        # pylint: disable-next=unused-argument
        def _stop_pool(*args, **kwargs):
            pool.close()

        results = [
            pool.apply_async(
                _process_keystore_file,
                (keystore_file, settings.KEYSTORES_PATH),
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


async def load_deposit_data() -> DepositData:
    """Loads and verifies deposit data."""
    with open(settings.DEPOSIT_DATA_PATH, 'r', encoding='utf-8') as f:
        deposit_data = json.load(f)

    credentials = get_eth1_withdrawal_credentials(settings.VAULT_CONTRACT_ADDRESS)
    leaves: list[tuple[bytes, int]] = []
    validators: list[Validator] = []
    for i, data in enumerate(deposit_data):
        validator = Validator(
            deposit_data_index=i,
            public_key=add_0x_prefix(data['pubkey']),
            signature=add_0x_prefix(data['signature']),
        )
        leaves.append((_encode_tx_validator(credentials, validator), i))
        validators.append(validator)

    tree = StandardMerkleTree.of(leaves, ['bytes', 'uint256'])
    await check_deposit_data_root(tree.root)

    logger.info('Loaded deposit data file %s', settings.DEPOSIT_DATA_PATH)
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


async def count_deposit_data_non_exited_keys() -> int:
    deposit_data = await load_deposit_data()
    validator_ids = [v.public_key for v in deposit_data.validators]
    validator_statuses = []

    for i in range(0, len(validator_ids), settings.VALIDATORS_FETCH_CHUNK_SIZE):
        validators = await consensus_client.get_validators_by_ids(
            validator_ids[i : i + settings.VALIDATORS_FETCH_CHUNK_SIZE]
        )
        validator_statuses.extend(validators['data'])

    count = 0
    for validator in validator_statuses:
        if validator['status'] not in EXITED_STATUSES:
            count += 1
    return count
