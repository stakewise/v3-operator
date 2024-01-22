import asyncio
import logging
import time
from random import shuffle

from aiohttp import ClientError
from eth_typing import BlockNumber
from tenacity import RetryError
from web3.types import HexStr

from src.common.contracts import keeper_contract
from src.common.exceptions import NotEnoughOracleApprovalsError
from src.common.execution import get_oracles
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import Oracles
from src.common.utils import get_current_timestamp, is_block_finalized, warning_verbose
from src.config.settings import settings
from src.exits.consensus import get_validator_public_keys
from src.exits.execution import submit_exit_signatures
from src.exits.typings import SignatureRotationRequest
from src.exits.utils import (
    get_oracle_outdated_signatures_response,
    send_signature_rotation_requests,
)
from src.validators.keystores.base import BaseKeystore

logger = logging.getLogger(__name__)


class ExitSignatureTask(BaseTask):
    keystore: BaseKeystore

    def __init__(self, keystore: BaseKeystore):
        self.keystore = keystore

    async def process_block(self) -> None:
        oracles = await get_oracles()
        update_block = await _fetch_last_update_block()
        if update_block and not await is_block_finalized(update_block):
            logger.info('Waiting for signatures update block %d to finalize...', update_block)
            return

        if update_block and not await _check_majority_oracles_synced(oracles, update_block):
            logger.info('Waiting for the majority of oracles to sync exit signatures')
            return

        outdated_indexes = await _fetch_outdated_indexes(oracles, update_block)
        if outdated_indexes:
            await _update_exit_signatures(
                keystore=self.keystore,
                oracles=oracles,
                outdated_indexes=outdated_indexes,
            )


async def _check_majority_oracles_synced(oracles: Oracles, update_block: BlockNumber) -> bool:
    threshold = oracles.validators_threshold
    pending = {
        asyncio.create_task(_fetch_last_update_block_replicas(replicas))
        for replicas in oracles.endpoints
    }
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            block_number = task.result()
            if not block_number or block_number < update_block:
                continue
            threshold -= 1
            if threshold <= 0:
                for task in pending:
                    task.cancel()
                return True
    return False


async def _fetch_last_update_block_replicas(replicas: list[str]) -> BlockNumber | None:
    results = await asyncio.gather(
        *[_fetch_exit_signature_block(endpoint) for endpoint in replicas], return_exceptions=True
    )
    blocks = []
    for res in results:
        if not isinstance(res, Exception) and res is not None:
            blocks.append(res)
    if blocks:
        return min(blocks)
    return None


async def _fetch_last_update_block() -> BlockNumber | None:
    last_event = await keeper_contract.get_exit_signatures_updated_event(vault=settings.vault)
    if last_event:
        return BlockNumber(last_event['blockNumber'])
    return None


async def _fetch_outdated_indexes(oracles: Oracles, update_block: BlockNumber | None) -> list[int]:
    endpoints = [endpoint for replicas in oracles.endpoints for endpoint in replicas]
    shuffle(endpoints)

    for oracle_endpoint in endpoints:
        try:
            response = await get_oracle_outdated_signatures_response(oracle_endpoint)
        except (ClientError, RetryError) as e:
            warning_verbose(str(e))
            continue
        if not update_block or response['exit_signature_block_number'] >= update_block:
            outdated_indexes = [val['index'] for val in response['validators']]
            metrics.outdated_signatures.set(len(outdated_indexes))
            return outdated_indexes
    raise RuntimeError('Oracles are down or have not synced exit signatures yet')


async def _update_exit_signatures(
    keystore: BaseKeystore,
    oracles: Oracles,
    outdated_indexes: list[int],
) -> None:
    """Fetches update signature requests from oracles."""
    logger.info('Starting exit signature rotation for %d validators', len(outdated_indexes))
    # pylint: disable=duplicate-code
    validators = await get_validator_public_keys(outdated_indexes)
    deadline = None
    approvals_min_interval = 1

    while True:
        approval_start_time = time.time()

        current_timestamp = get_current_timestamp()
        if not deadline or deadline <= current_timestamp:
            deadline = current_timestamp + oracles.signature_validity_period
            oracles_request = await _get_oracles_request(
                oracles=oracles,
                keystore=keystore,
                validators=validators,
            )

        if not oracles_request.public_keys:
            logger.warning('No keys to rotate exit signatures')
            return
        try:
            # send approval request to oracles
            oracles_approval = await send_signature_rotation_requests(oracles, oracles_request)
            break
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Not enough oracle approvals for exit signature update: %d. Threshold is %d',
                e.num_votes,
                e.threshold,
            )
        approvals_time = time.time() - approval_start_time
        await asyncio.sleep(approvals_min_interval - approvals_time)

    tx_hash = await submit_exit_signatures(oracles_approval)
    if not tx_hash:
        return

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
    keystore: BaseKeystore,
    validators: dict[int, HexStr],
) -> SignatureRotationRequest:
    """Fetches approval from oracles."""
    # get exit signature shards
    request = SignatureRotationRequest(
        vault_address=settings.vault,
        public_keys=[],
        public_key_shards=[],
        exit_signature_shards=[],
        deadline=get_current_timestamp() + oracles.signature_validity_period,
    )
    failed_indexes = []
    exit_rotation_batch_limit = oracles.validators_exit_rotation_batch_limit

    for validator_index, public_key in validators.items():
        if len(request.public_keys) >= exit_rotation_batch_limit:
            break

        if public_key in keystore:
            shards = await keystore.get_exit_signature_shards(
                validator_index=validator_index,
                public_key=public_key,
                oracles=oracles,
                fork=settings.network_config.SHAPELLA_FORK,
            )
        else:
            failed_indexes.append(validator_index)
            continue

        request.public_keys.append(public_key)
        request.public_key_shards.append(shards.public_keys)
        request.exit_signature_shards.append(shards.exit_signatures)

    if failed_indexes:
        logger.warning(
            'Failed to rotate validator exit signature for indexes: %s. '
            'Reason: public key not found in keystores or remote signer',
            _format_indexes(failed_indexes),
        )

    return request


def _format_indexes(indexes: list[int], max_len: int = 10) -> str:
    if len(indexes) <= max_len:
        return ', '.join(str(i) for i in indexes)

    return f"{', '.join(str(i) for i in indexes)}..."
