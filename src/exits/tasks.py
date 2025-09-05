import asyncio
import logging
import time
from itertools import chain
from random import shuffle

from aiohttp import ClientError
from eth_typing import BlockNumber, ChecksumAddress
from sw_utils import InterruptHandler
from sw_utils.typings import Oracle, ProtocolConfig
from tenacity import RetryError
from web3.types import HexStr

from src.common.app_state import AppState
from src.common.clients import execution_client
from src.common.contracts import keeper_contract
from src.common.exceptions import NotEnoughOracleApprovalsError
from src.common.execution import get_protocol_config
from src.common.metrics import metrics
from src.common.tasks import BaseTask
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
from src.validators.signing.common import get_encrypted_exit_signature_shards

logger = logging.getLogger(__name__)


class ExitSignatureTask(BaseTask):
    def __init__(self, keystore: BaseKeystore | None):
        self.keystore = keystore

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        if self.keystore is None:
            return

        protocol_config = await get_protocol_config()
        for vault in settings.vaults:
            update_block = await _fetch_last_update_block(vault)

            logger.debug('last exit signature update block %s for vault %s', update_block, vault)

            if update_block and not await is_block_finalized(update_block):
                logger.info(
                    'Waiting for signatures update block %d for vault %s to finalize...',
                    update_block,
                    vault,
                )
                return

            if update_block and not await _check_majority_oracles_synced(
                protocol_config, update_block, vault
            ):
                logger.info('Waiting for the majority of oracles to sync exit signatures')
                return

            outdated_indexes = await _fetch_outdated_indexes(
                protocol_config.oracles, update_block, vault=vault
            )
            if outdated_indexes:
                await _update_exit_signatures(
                    vault=vault,
                    keystore=self.keystore,
                    protocol_config=protocol_config,
                    outdated_indexes=outdated_indexes,
                )


async def _check_majority_oracles_synced(
    protocol_config: ProtocolConfig, update_block: BlockNumber, vault: ChecksumAddress
) -> bool:
    threshold = protocol_config.validators_threshold
    endpoints = [oracle.endpoints for oracle in protocol_config.oracles]

    pending = {
        asyncio.create_task(_fetch_last_update_block_replicas(replicas, vault=vault))
        for replicas in endpoints
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


async def _fetch_last_update_block_replicas(
    replicas: list[str], vault: ChecksumAddress
) -> BlockNumber | None:
    results = await asyncio.gather(
        *[_fetch_exit_signature_block(endpoint, vault=vault) for endpoint in replicas],
        return_exceptions=True,
    )
    blocks: list[BlockNumber] = []
    for res in results:
        if not isinstance(res, BaseException) and res is not None:
            blocks.append(res)
    if blocks:
        return min(blocks)
    return None


async def _fetch_last_update_block(vault: ChecksumAddress) -> BlockNumber | None:
    app_state = AppState()
    update_cache = app_state.exit_signature_update_cache[vault]

    from_block: BlockNumber | None = None
    if (checkpoint_block := update_cache.checkpoint_block) is not None:
        from_block = BlockNumber(checkpoint_block + 1)

    to_block = await execution_client.eth.get_block_number()

    if from_block is not None and from_block > to_block:
        return update_cache.last_event_block

    last_event = await keeper_contract.get_exit_signatures_updated_event(
        vault=vault, from_block=from_block, to_block=to_block
    )
    update_cache.checkpoint_block = to_block

    if last_event:
        update_cache.last_event_block = BlockNumber(last_event['blockNumber'])

    return update_cache.last_event_block


async def _fetch_outdated_indexes(
    oracles: list[Oracle], update_block: BlockNumber | None, vault: ChecksumAddress
) -> list[int]:
    endpoints = list(chain.from_iterable([oracle.endpoints for oracle in oracles]))
    shuffle(endpoints)  # nosec

    for oracle_endpoint in endpoints:
        try:
            response = await get_oracle_outdated_signatures_response(oracle_endpoint, vault=vault)
        except (ClientError, RetryError) as e:
            warning_verbose(str(e))
            continue
        if response['exit_signature_block_number'] is None:
            continue
        if not update_block or response['exit_signature_block_number'] >= update_block:
            outdated_indexes = [val['index'] for val in response['validators']]
            metrics.outdated_signatures.labels(network=settings.network).set(len(outdated_indexes))
            return outdated_indexes
    raise RuntimeError('Oracles are down or have not synced exit signatures yet')


async def _update_exit_signatures(
    vault: ChecksumAddress,
    keystore: BaseKeystore,
    protocol_config: ProtocolConfig,
    outdated_indexes: list[int],
) -> None:
    """Fetches update signature requests from oracles."""
    logger.info('Starting exit signature rotation for %d validators', len(outdated_indexes))
    validators = await get_validator_public_keys(outdated_indexes)
    approvals_min_interval = 1
    deadline: int | None = None
    oracles_request: SignatureRotationRequest | None = None

    while True:
        approval_start_time = time.time()

        current_timestamp = get_current_timestamp()
        if not oracles_request or deadline is None or deadline <= current_timestamp:
            deadline = current_timestamp + protocol_config.signature_validity_period
            oracles_request = await _get_oracles_request(
                vault=vault,
                protocol_config=protocol_config,
                keystore=keystore,
                validators=validators,
            )

        if not oracles_request.public_keys:
            logger.warning('No keys to rotate exit signatures')
            return
        try:
            # send approval request to oracles
            oracles_approval = await send_signature_rotation_requests(
                protocol_config, oracles_request
            )
            break
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Not enough oracle approvals for exit signature update: %d. Threshold is %d',
                e.num_votes,
                e.threshold,
            )
        approvals_time = time.time() - approval_start_time
        await asyncio.sleep(approvals_min_interval - approvals_time)

    tx_hash = await submit_exit_signatures(approval=oracles_approval, vault_address=vault)
    if not tx_hash:
        return

    logger.info(
        'Successfully rotated exit signatures for validators with indexes %s, tx hash: %s',
        ', '.join([str(index) for index in outdated_indexes]),
        tx_hash,
    )


async def _fetch_exit_signature_block(
    oracle_endpoint: str, vault: ChecksumAddress
) -> BlockNumber | None:
    data = await get_oracle_outdated_signatures_response(oracle_endpoint, vault=vault)
    block_number = data['exit_signature_block_number']
    if block_number is None:
        return None
    return BlockNumber(block_number)


async def _get_oracles_request(
    vault: ChecksumAddress,
    protocol_config: ProtocolConfig,
    keystore: BaseKeystore,
    validators: dict[int, HexStr],
) -> SignatureRotationRequest:
    """Fetches approval from oracles."""
    # get exit signature shards
    request = SignatureRotationRequest(
        vault_address=vault,
        public_keys=[],
        public_key_shards=[],
        exit_signature_shards=[],
        deadline=get_current_timestamp() + protocol_config.signature_validity_period,
    )
    failed_indexes = []
    exit_rotation_batch_limit = protocol_config.validators_exit_rotation_batch_limit

    for validator_index, public_key in validators.items():
        if len(request.public_keys) >= exit_rotation_batch_limit:
            break

        if public_key in keystore:
            shards = await get_encrypted_exit_signature_shards(
                keystore=keystore,
                public_key=public_key,
                validator_index=validator_index,
                protocol_config=protocol_config,
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
    trim_indexes = indexes[:max_len]
    res = ', '.join(str(i) for i in trim_indexes)

    if len(indexes) <= max_len:
        return res

    return res + '...'
