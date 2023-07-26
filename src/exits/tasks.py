import asyncio
import logging
import random
import time
from urllib.parse import urljoin

import aiohttp
from sw_utils.decorators import retry_aiohttp_errors
from web3.types import HexStr

from src.common.clients import consensus_client
from src.common.metrics import metrics
from src.common.typings import Oracles
from src.config.settings import OUTDATED_SIGNATURES_URL_PATH, settings, DEFAULT_RETRY_TIME
from src.exits.consensus import get_validator_public_keys
from src.exits.execution import submit_exit_signatures
from src.exits.typings import OraclesApproval, SignatureRotationRequest
from src.exits.utils import send_signature_rotation_requests
from src.validators.signing import get_exit_signature_shards
from src.validators.typings import Keystores

logger = logging.getLogger(__name__)


async def fetch_outdated_indexes(oracles: Oracles) -> list[int]:
    random_oracle = random.choice(oracles.endpoints)  # nosec
    outdated_indexes = await _fetch_outdated_indexes(random_oracle)
    metrics.outdated_signatures.set(len(outdated_indexes))
    return outdated_indexes


async def wait_oracle_signature_update(
    updated_indexes: list[int], oracle_endpoint: str, max_time: int | float = 0
) -> None:
    """
    Wait the oracle `oracle_endpoint` reads and processes `ExitSignatureUpdate` event
    for validator indexes `updated_indexes`.
    """
    elapsed = 0.0
    start_time = time.time()

    while elapsed <= max_time:
        outdated_indexes = await _fetch_outdated_indexes(oracle_endpoint)

        if not set(outdated_indexes) & set(updated_indexes):
            return

        await asyncio.sleep(float(settings.network_config.SECONDS_PER_BLOCK))
        elapsed = time.time() - start_time

    raise asyncio.TimeoutError(
        f'Timeout exceeded for wait_oracle_signature_block_update for {oracle_endpoint}'
    )


async def update_exit_signatures(
    keystores: Keystores, oracles: Oracles, outdated_indexes: list[int]
) -> None:
    """Fetches update signature requests from oracles."""
    exit_rotation_batch_limit = oracles.validators_exit_rotation_batch_limit
    outdated_indexes = outdated_indexes[:exit_rotation_batch_limit]

    logger.info('Started exit signature rotation for %d validators', len(outdated_indexes))

    validators = await get_validator_public_keys(outdated_indexes)
    oracles_approval = await get_oracles_approval(
        oracles=oracles,
        keystores=keystores,
        validators=validators,
    )

    await submit_exit_signatures(oracles_approval)
    logger.info(
        'Successfully rotated exit signatures for validators with indexes %s',
        ', '.join([str(index) for index in outdated_indexes]),
    )


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def _fetch_outdated_indexes(oracle_endpoint: str) -> list[int]:
    path = OUTDATED_SIGNATURES_URL_PATH.format(vault=settings.vault)
    url = urljoin(oracle_endpoint, path)

    async with aiohttp.ClientSession() as session:
        async with session.get(url=url) as response:
            response.raise_for_status()
            data = await response.json()
    return [x.get('index') for x in data]


async def get_oracles_approval(
    oracles: Oracles, keystores: Keystores, validators: dict[int, HexStr]
) -> OraclesApproval:
    """Fetches approval from oracles."""
    fork = await consensus_client.get_consensus_fork()

    # get exit signature shards
    request = SignatureRotationRequest(
        vault_address=settings.vault,
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
    signatures, ipfs_hash = await send_signature_rotation_requests(oracles, request)
    logger.info('Fetched updated signature for validators: count=%d', len(validators))
    return OraclesApproval(
        signatures=signatures,
        ipfs_hash=ipfs_hash,
    )
