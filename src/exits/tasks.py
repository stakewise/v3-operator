import asyncio
import logging
import random
import time

from eth_typing import BlockNumber, BLSPubkey
from web3 import Web3
from web3.types import HexStr

from src.common.clients import consensus_client
from src.common.contracts import keeper_contract
from src.common.execution import get_oracles
from src.common.metrics import metrics
from src.common.typings import Oracles
from src.common.utils import get_current_timestamp, wait_block_finalization
from src.config.settings import (
    ORACLE_SIGNATURE_UPDATE_SYNC_DELAY,
    ORACLES_SIGNATURE_UPDATE_SYNC_TIMEOUT,
    settings,
)
from src.exits.consensus import get_validator_public_keys
from src.exits.execution import submit_exit_signatures
from src.exits.typings import SignatureRotationRequest
from src.exits.utils import (
    get_oracle_outdated_signatures_response,
    send_signature_rotation_requests,
)
from src.validators.signing.local import get_exit_signature_shards
from src.validators.signing.remote import (
    RemoteSignerConfiguration,
    get_exit_signature_shards_remote_signer,
)
from src.validators.typings import Keystores

logger = logging.getLogger(__name__)


async def update_exit_signatures_periodically(
    keystores: Keystores,
    remote_signer_config: RemoteSignerConfiguration | None,
):
    # Oracle may have lag if operator was stopped
    # during `update_exit_signatures_periodically` process.
    # Wait oracles sync.
    oracles = await get_oracles()
    await _wait_oracles_signature_update(oracles)

    while True:
        timer_start = time.time()

        try:
            oracles = await get_oracles()

            oracle_replicas = random.choice(oracles.endpoints)  # nosec
            oracle_endpoint = random.choice(oracle_replicas)  # nosec
            outdated_indexes = await _fetch_outdated_indexes(oracle_endpoint)

            if outdated_indexes:
                await _update_exit_signatures(
                    keystores=keystores,
                    remote_signer_config=remote_signer_config,
                    oracles=oracles,
                    outdated_indexes=outdated_indexes,
                )

                # Wait oracles sync.
                await _wait_oracles_signature_update(oracles)
        except Exception as e:
            logger.exception(e)

        elapsed = time.time() - timer_start
        await asyncio.sleep(float(settings.network_config.SECONDS_PER_BLOCK) - elapsed)


async def _fetch_outdated_indexes(oracle_endpoint) -> list[int]:
    response = await get_oracle_outdated_signatures_response(oracle_endpoint)
    outdated_indexes = [val['index'] for val in response['validators']]

    metrics.outdated_signatures.set(len(outdated_indexes))
    return outdated_indexes


async def _wait_oracles_signature_update(oracles: Oracles) -> None:
    last_event = await keeper_contract.get_exit_signatures_updated_event(vault=settings.vault)
    if not last_event:
        return
    update_block = BlockNumber(last_event['blockNumber'])

    logger.info('Waiting for block %d finalization...', update_block)
    await wait_block_finalization(update_block)

    oracle_tasks = {
        asyncio.create_task(
            _wait_oracle_signature_update(
                exit_signature_update_block=update_block,
                oracle_endpoint=endpoint,
                max_time=ORACLES_SIGNATURE_UPDATE_SYNC_TIMEOUT,
            )
        )
        for replicas in oracles.endpoints
        for endpoint in replicas
    }
    while oracle_tasks:
        done, oracle_tasks = await asyncio.wait(oracle_tasks, return_when=asyncio.FIRST_COMPLETED)
        if done:
            for pending_task in oracle_tasks:
                pending_task.cancel()
    logger.info('Oracles have fetched exit signatures update')


async def _wait_oracle_signature_update(
    exit_signature_update_block: BlockNumber, oracle_endpoint: str, max_time: int | float = 0
) -> None:
    """
    Wait the oracle `oracle_endpoint` reads and processes `ExitSignatureUpdate` event
    in the block `exit_signature_update_block`.
    """
    elapsed = 0.0
    start_time = time.time()

    while elapsed <= max_time:
        oracle_block = await _fetch_exit_signature_block(oracle_endpoint)
        if oracle_block and oracle_block >= exit_signature_update_block:
            return

        logger.info(
            'Waiting for %s to sync block %d...', oracle_endpoint, exit_signature_update_block
        )
        await asyncio.sleep(ORACLE_SIGNATURE_UPDATE_SYNC_DELAY)
        elapsed = time.time() - start_time

    raise asyncio.TimeoutError(
        f'Timeout exceeded for wait_oracle_signature_block_update for {oracle_endpoint}'
    )


async def _update_exit_signatures(
    keystores: Keystores,
    remote_signer_config: RemoteSignerConfiguration | None,
    oracles: Oracles,
    outdated_indexes: list[int],
) -> None:
    """Fetches update signature requests from oracles."""
    exit_rotation_batch_limit = oracles.validators_exit_rotation_batch_limit
    outdated_indexes = outdated_indexes[:exit_rotation_batch_limit]

    logger.info('Starting exit signature rotation for %d validators', len(outdated_indexes))
    # pylint: disable=duplicate-code
    validators = await get_validator_public_keys(outdated_indexes)
    deadline = None
    while True:
        current_timestamp = get_current_timestamp()
        if not deadline or deadline <= current_timestamp:
            deadline = current_timestamp + oracles.signature_validity_period
            oracles_request = await _get_oracles_request(
                oracles=oracles,
                keystores=keystores,
                remote_signer_config=remote_signer_config,
                validators=validators,
            )

        if not oracles_request.public_keys:
            logger.warning('No keys to rotate exit signatures')
            return
        try:
            # send approval request to oracles
            oracles_approval = await send_signature_rotation_requests(oracles, oracles_request)
            logger.info('Fetched updated signature for validators: count=%d', len(validators))
            break
        except Exception as e:
            logger.exception(e)

    tx_hash = await submit_exit_signatures(oracles_approval)
    logger.info(
        'Successfully rotated exit signatures for validators with indexes %s, tx hash: %s',
        ', '.join([str(index) for index in outdated_indexes]),
        tx_hash,
    )


async def _fetch_exit_signature_block(oracle_endpoint: str) -> BlockNumber | None:
    data = await get_oracle_outdated_signatures_response(oracle_endpoint)
    block_number = data['exit_signature_block_number']
    if block_number is None:
        return None
    return BlockNumber(block_number)


async def _get_oracles_request(
    oracles: Oracles,
    keystores: Keystores,
    remote_signer_config: RemoteSignerConfiguration | None,
    validators: dict[int, HexStr],
) -> SignatureRotationRequest:
    """Fetches approval from oracles."""
    fork = await consensus_client.get_consensus_fork()

    # get exit signature shards
    request = SignatureRotationRequest(
        vault_address=settings.vault,
        public_keys=[],
        public_key_shards=[],
        exit_signature_shards=[],
        deadline=get_current_timestamp() + oracles.signature_validity_period,
    )
    for validator_index, public_key in validators.items():
        if len(keystores) > 0 and public_key in keystores:
            shards = get_exit_signature_shards(
                validator_index=validator_index,
                private_key=keystores[public_key],
                oracles=oracles,
                fork=fork,
            )
        elif remote_signer_config and public_key in remote_signer_config.pubkeys_to_shares:
            # pylint: disable=duplicate-code
            pubkey_shares = remote_signer_config.pubkeys_to_shares[public_key]
            shards = await get_exit_signature_shards_remote_signer(
                validator_index=validator_index,
                validator_pubkey_shares=[BLSPubkey(Web3.to_bytes(hexstr=s)) for s in pubkey_shares],
                oracles=oracles,
                fork=fork,
            )
        else:
            logger.warning(
                'Failed to rotate validator exit signature: '
                'public key %s not found in keystores or remote signer',
                public_key,
            )
            continue

        request.public_keys.append(public_key)
        request.public_key_shards.append(shards.public_keys)
        request.exit_signature_shards.append(shards.exit_signatures)

    return request
