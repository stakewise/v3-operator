import dataclasses
import json
import logging
import random
from multiprocessing import Pool
from os import listdir
from os.path import isfile, join

import aiohttp
import backoff
import milagro_bls_binding as bls
from aiohttp import ClientError
from eth_typing import ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from multiproof import StandardMerkleTree
from staking_deposit.key_handling.keystore import ScryptKeystore
from sw_utils import get_eth1_withdrawal_credentials
from web3 import Web3

from src.config.settings import (
    DEFAULT_RETRY_TIME,
    DEPOSIT_DATA_PATH,
    KEYSTORES_PASSWORD_PATH,
    KEYSTORES_PATH,
    VAULT_CONTRACT_ADDRESS,
)
from src.validators.database import get_next_validator_index
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
    Keystores,
    OracleApproval,
    Oracles,
    Validator,
)

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


connection_errors = (
    aiohttp.ClientConnectionError,
    aiohttp.ClientConnectorError,
    aiohttp.ServerConnectionError,
)


@backoff.on_exception(backoff.expo, connection_errors, max_time=DEFAULT_RETRY_TIME)
async def send_approval_request(
    session: aiohttp.ClientSession, endpoint: str, payload: dict
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
        validator_index = get_next_validator_index(list(latest_public_keys))
        if validator_index != payload['validator_index']:
            raise ValidatorIndexChangedError from e

        raise e

    return OracleApproval(
        ipfs_hash=data['ipfs_hash'], signature=Web3.to_bytes(hexstr=data['signature'])
    )


def load_keystores() -> Keystores:
    """Extracts private keys from the keystores."""

    keystores_password = _load_keystores_password()
    files = listdir(KEYSTORES_PATH)
    logger.info('Loading keystores from %s...', KEYSTORES_PATH)
    with Pool() as pool:
        # pylint: disable-next=unused-argument
        def _stop_pool(*args, **kwargs):
            pool.terminate()

        results = [
            pool.apply_async(
                _process_keystore_file,
                [file, keystores_password],
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
        keystores = Keystores(dict(existing_keys))

    logger.info('Loaded %d keystores', len(keystores))
    return keystores


async def load_deposit_data() -> DepositData:
    """Loads and verifies deposit data."""
    with open(DEPOSIT_DATA_PATH, 'r', encoding='utf-8') as f:
        deposit_data = json.load(f)

    credentials = get_eth1_withdrawal_credentials(VAULT_CONTRACT_ADDRESS)
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

    logger.info('Loaded deposit data file %s', DEPOSIT_DATA_PATH)
    return DepositData(validators=validators, tree=tree)


def _process_keystore_file(
    file_name: str, keystores_password: str
) -> tuple[HexStr, BLSPrivkey] | None:
    file_path = join(KEYSTORES_PATH, file_name)
    if not (isfile(file_path) and file_name.startswith('keystore')):
        return None

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


def _load_keystores_password() -> str:
    with open(KEYSTORES_PASSWORD_PATH, 'r', encoding='utf-8') as f:
        return f.read().strip()
