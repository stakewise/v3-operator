import logging
import time

from eth_typing import BlockNumber
from sw_utils import ExtendedAsyncBeacon
from sw_utils.consensus import ACTIVE_STATUSES, ValidatorStatus
from web3 import AsyncWeb3
from web3.types import BlockData, Timestamp

from src.common.utils import calc_slot_by_block_number, calc_slot_by_block_timestamp
from src.config.settings import settings
from src.nodes.status_history import SyncStatusHistory
from src.validators.keystores.local import LocalKeystore

logger = logging.getLogger(__name__)


async def get_consensus_node_status(consensus_client: ExtendedAsyncBeacon) -> dict:
    try:
        syncing = (await consensus_client.get_syncing())['data']
    except Exception:
        return {}

    eta = await _calc_consensus_eta(
        consensus_syncing=syncing,
        sync_status_history=SyncStatusHistory().load_history(),
    )

    return {
        'is_syncing': syncing['is_syncing'],
        'sync_distance': syncing['sync_distance'],
        'eta': eta,
    }


async def get_execution_node_status(execution_client: AsyncWeb3) -> dict:
    try:
        latest_block = await execution_client.eth.get_block('latest')
    except Exception:
        return {}

    sync_distance = (
        int(time.time()) - latest_block['timestamp']
    ) // settings.network_config.SECONDS_PER_BLOCK
    allowed_delay = 5
    is_syncing = sync_distance > allowed_delay

    if is_syncing:
        eta = await _calc_execution_eta(
            execution_client=execution_client,
            sync_status_history=SyncStatusHistory().load_history(),
            latest_block=latest_block,
        )
    else:
        eta = 0

    return {
        'is_syncing': is_syncing,
        'block_number': latest_block['number'],
        'eta': eta,
    }


async def get_validator_activity_stats(consensus_client: ExtendedAsyncBeacon) -> dict:
    """
    Returns the activity statistics of validators.
    Format: `{'active': int, 'total': int}`
    """
    keystore_files = LocalKeystore.list_keystore_files()
    stats: dict[str, int] = {'active': 0, 'total': 0}
    public_keys: list[str] = []

    # Read public keys from keystore files
    for keystore_file in keystore_files:
        _, public_key = LocalKeystore.read_keystore_file(keystore_file)
        public_keys.append(public_key)

    stats['total'] = len(public_keys)

    # Get validator statuses
    validators = (await consensus_client.get_validators_by_ids(public_keys))['data']

    # Calc number of active validators
    for validator in validators:
        status = ValidatorStatus(validator['status'])
        if status in ACTIVE_STATUSES:
            stats['active'] += 1

    return stats


async def _calc_consensus_eta(
    consensus_syncing: dict, sync_status_history: list[dict]
) -> int | None:
    if len(sync_status_history) < 2:
        return None

    sync_distance = int(consensus_syncing['sync_distance'])
    allowed_delay = 1

    if sync_distance <= allowed_delay:
        return 0

    first_timestamp = int(sync_status_history[0]['timestamp'])
    last_timestamp = int(sync_status_history[-1]['timestamp'])
    first_slot = int(sync_status_history[0]['slot'])
    last_slot = int(sync_status_history[-1]['slot'])
    consensus_speed = (last_slot - first_slot) / (last_timestamp - first_timestamp)

    consensus_eta = int(sync_distance / consensus_speed) if consensus_speed > 0 else None
    return consensus_eta


async def _calc_execution_eta(
    execution_client: AsyncWeb3, sync_status_history: list[dict], latest_block: BlockData
) -> int | None:
    if len(sync_status_history) < 2:
        return None

    latest_block_slot = calc_slot_by_block_timestamp(latest_block['timestamp'])
    head_slot = calc_slot_by_block_timestamp(Timestamp(int(time.time())))

    execution_speed = await _calc_execution_speed_slots(
        sync_status_history=sync_status_history,
        execution_client=execution_client,
    )
    if execution_speed is None or execution_speed <= 0:
        return None

    # Calculate ETA
    execution_eta = int((head_slot - latest_block_slot) / execution_speed)
    return execution_eta


async def _calc_execution_speed_slots(
    sync_status_history: list[dict], execution_client: AsyncWeb3
) -> float | None:

    # Get first and last blocks from the history
    first_block_number = BlockNumber(int(sync_status_history[0]['block_number']))
    last_block_number = BlockNumber(int(sync_status_history[-1]['block_number']))

    # Calculate execution speed in slots per second (not blocks per second)
    try:
        first_block_slot = await calc_slot_by_block_number(
            first_block_number, execution_client=execution_client
        )
        last_block_slot = await calc_slot_by_block_number(
            last_block_number, execution_client=execution_client
        )
    except Exception:
        return None

    first_timestamp = int(sync_status_history[0]['timestamp'])
    last_timestamp = int(sync_status_history[-1]['timestamp'])
    execution_speed = (last_block_slot - first_block_slot) / (last_timestamp - first_timestamp)
    return execution_speed
