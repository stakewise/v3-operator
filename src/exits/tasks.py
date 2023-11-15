import asyncio
import logging
from random import shuffle

from eth_typing import BlockNumber, BLSPubkey
from web3 import Web3
from web3.types import HexStr

from src.common.contracts import keeper_contract
from src.common.exceptions import NotEnoughOracleApprovalsError
from src.common.execution import get_oracles
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import Oracles
from src.common.utils import get_current_timestamp, is_block_finalized
from src.config.settings import settings
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


class ExitSignatureTask(BaseTask):
    keystores: Keystores
    remote_signer_config: RemoteSignerConfiguration | None

    def __init__(
        self, keystores: Keystores, remote_signer_config: RemoteSignerConfiguration | None
    ):
        self.keystores = keystores
        self.remote_signer_config = remote_signer_config

    async def process(self) -> None:
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
                keystores=self.keystores,
                remote_signer_config=self.remote_signer_config,
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
        response = await get_oracle_outdated_signatures_response(oracle_endpoint)
        if not update_block or response['exit_signature_block_number'] >= update_block:
            outdated_indexes = [val['index'] for val in response['validators']]
            metrics.outdated_signatures.set(len(outdated_indexes))
            return outdated_indexes
    raise RuntimeError('Oracles have not synced exit signatures yet')


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
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Failed to fetch oracle exit signatures update. Received %d out of %d, '
                'the oracles with endpoints %s have failed to respond.',
                e.num_votes,
                e.threshold,
                ', '.join(e.failed_endpoints),
            )

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
    keystores: Keystores,
    remote_signer_config: RemoteSignerConfiguration | None,
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

    for validator_index, public_key in validators.items():
        if len(keystores) > 0 and public_key in keystores:
            shards = get_exit_signature_shards(
                validator_index=validator_index,
                private_key=keystores[public_key],
                oracles=oracles,
                fork=settings.network_config.SHAPELLA_FORK,
            )
        elif remote_signer_config and public_key in remote_signer_config.pubkeys_to_shares:
            # pylint: disable=duplicate-code
            pubkey_shares = remote_signer_config.pubkeys_to_shares[public_key]
            shards = await get_exit_signature_shards_remote_signer(
                validator_index=validator_index,
                validator_pubkey_shares=[BLSPubkey(Web3.to_bytes(hexstr=s)) for s in pubkey_shares],
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
