import logging
import posixpath
import random
from urllib.parse import urljoin

import aiohttp
from web3.types import HexStr

from src.config.settings import SIGNATURES_URL_PATH, VAULT_CONTRACT_ADDRESS
from src.exits.consensus import get_validator_public_keys
from src.exits.execution import register_exit_signatures
from src.exits.typings import OraclesApproval, SignatureRotationRequest
from src.exits.utils import send_approval_requests
from src.validators.consensus import get_consensus_fork
from src.validators.execution import check_operator_balance, get_oracles
from src.validators.signing import get_exit_signature_shards
from src.validators.typings import Keystores

logger = logging.getLogger(__name__)


async def update_exit_signatures(keystores: Keystores) -> None:
    """Fetches update signature requests from oracles."""
    oracles = await get_oracles()

    random_oracle = random.choice(oracles.endpoints)  # nosec
    rotated_indexes = await _fetch_outdated_indexes(random_oracle)
    if not rotated_indexes:
        return

    logger.info('Started exit signature rotation for %d validators', len(rotated_indexes))

    validators = await get_validator_public_keys(rotated_indexes)
    oracles_approval = await get_oracles_approval(
        oracles=oracles,
        keystores=keystores,
        validators=validators,
    )

    await register_exit_signatures(oracles_approval)
    logger.info(
        'Successfully managed exit signature rotation for validators with indexes %s',
        ', '.join([str(index) for index in rotated_indexes])
    )

    # check balance after transaction
    await check_operator_balance()


async def _fetch_outdated_indexes(oracle_endpoint: str) -> list[int]:
    path = posixpath.join(SIGNATURES_URL_PATH, VAULT_CONTRACT_ADDRESS)
    url = urljoin(oracle_endpoint, path)

    async with aiohttp.ClientSession() as session:
        async with session.get(url=url) as response:
            response.raise_for_status()
            data = await response.json()
    return [x.get('index') for x in data]


async def get_oracles_approval(
    oracles,
    keystores: Keystores,
    validators: dict[int, HexStr]
) -> OraclesApproval:
    """Fetches approval from oracles."""
    # get latest oracles
    fork = await get_consensus_fork()

    # get exit signature shards
    request = SignatureRotationRequest(
        vault_address=VAULT_CONTRACT_ADDRESS,
        public_keys=[],
        public_key_shards=[],
        exit_signature_shards=[],
    )
    for validator_index, public_key in validators.items():
        shards = get_exit_signature_shards(
            validator_index=validator_index,
            private_key=keystores[public_key],
            oracles=oracles,
            fork=fork,
        )
        if not shards:
            break

        request.public_keys.append(public_key)
        request.public_key_shards.append(shards.public_keys)
        request.exit_signature_shards.append(shards.exit_signatures)

    # send approval request to oracles
    signatures, ipfs_hash = await send_approval_requests(oracles, request)
    logger.info(
        'Fetched ... for validators: count=%d',
        len(validators)
    )
    return OraclesApproval(
        signatures=signatures,
        ipfs_hash=ipfs_hash,
    )
