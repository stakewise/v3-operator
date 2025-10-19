import logging
import time

from eth_typing import BlockNumber
from sw_utils import ExtendedAsyncBeacon
from sw_utils.consensus import ACTIVE_STATUSES, ValidatorStatus
from web3 import AsyncWeb3
from web3.types import BlockData, Timestamp

from src.common.utils import calc_slot_by_block_number, calc_slot_by_block_timestamp
from src.config.settings import settings
from src.nodes.status_history import SYNC_STATUS_INTERVAL, SyncStatusHistory
from src.nodes.typings import StatusHistoryRecord
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
        'head_slot': int(syncing['head_slot']),
        'sync_distance': int(syncing['sync_distance']),
        'eta': int(eta) if eta is not None else None,
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
    sync_status_history = SyncStatusHistory().load_history()

    is_initial_sync = latest_block['number'] == 0

    # Assume initial sync is 90% of the total sync process
    initial_sync_ratio = 0.9
    initial_sync_eta = settings.network_config.NODE_CONFIG.INITIAL_SYNC_ETA.total_seconds()
    regular_sync_eta = (1 - initial_sync_ratio) * initial_sync_eta
    eta: float
    progress: float

    if is_initial_sync:
        initial_progress = await _calc_initial_execution_sync_progress(execution_client)
        progress = initial_sync_ratio * initial_progress
        initial_eta = initial_sync_eta * (1 - initial_progress)
        eta = initial_eta + (1 - initial_sync_ratio) * initial_sync_eta
    elif is_syncing:
        regular_progress = await _calc_regular_execution_sync_progress(
            execution_client=execution_client,
            sync_status_history=sync_status_history,
            latest_block=latest_block,
        )
        progress = initial_sync_ratio + (1 - initial_sync_ratio) * regular_progress
        eta = (
            await _calc_regular_execution_eta(
                execution_client=execution_client,
                sync_status_history=sync_status_history,
                latest_block=latest_block,
            )
            or regular_sync_eta
        )
    else:
        progress = 1.0
        eta = 0

    return {
        'is_syncing': is_syncing,
        'latest_block_number': latest_block['number'],
        'sync_distance': sync_distance,
        'eta': int(eta),
        'progress': round(progress * 100),  # percentage
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
        _, public_key = LocalKeystore.parse_keystore_file(keystore_file)
        public_keys.append(public_key)

    stats['total'] = len(public_keys)

    stats['active'] = await _get_number_of_active_validators(
        public_keys=public_keys, consensus_client=consensus_client
    )

    return stats


async def _get_number_of_active_validators(
    public_keys: list[str], consensus_client: ExtendedAsyncBeacon
) -> int:
    if not public_keys:
        return 0

    active_count = 0
    validators = (await consensus_client.get_validators_by_ids(public_keys))['data']

    for validator in validators:
        status = ValidatorStatus(validator['status'])
        if status in ACTIVE_STATUSES:
            active_count += 1

    return active_count


async def _calc_consensus_eta(
    consensus_syncing: dict, sync_status_history: list[StatusHistoryRecord]
) -> float | None:
    if len(sync_status_history) < 2:
        return None

    sync_distance = int(consensus_syncing['sync_distance'])
    allowed_delay = 1

    if sync_distance <= allowed_delay:
        return 0.0

    consensus_speed = _calc_consensus_speed(sync_status_history)

    if consensus_speed is None or consensus_speed <= 0:
        return None

    return sync_distance / consensus_speed


def _calc_consensus_speed(sync_status_history: list[StatusHistoryRecord]) -> float | None:
    if len(sync_status_history) < 2:
        return None

    # Find two consecutive records with timestamp difference close to the sync interval
    # Ensure the node was working between records
    # Also avoid small time differences
    sync_interval_max_diff = 3.0
    first_record = None
    last_record = None

    for i in range(len(sync_status_history) - 1, 0, -1):
        curr = sync_status_history[i]
        prev = sync_status_history[i - 1]
        sync_interval_diff = abs(curr.timestamp - prev.timestamp - SYNC_STATUS_INTERVAL)

        # Find the moment when the node was actually syncing
        slots_diff = curr.slot - prev.slot
        slots_diff_min = 2 * SYNC_STATUS_INTERVAL / settings.network_config.SECONDS_PER_SLOT

        if sync_interval_diff < sync_interval_max_diff and slots_diff > slots_diff_min:
            first_record = prev
            last_record = curr
            break

    if first_record is None or last_record is None:
        return None

    first_timestamp = first_record.timestamp
    last_timestamp = last_record.timestamp

    first_slot = first_record.slot
    last_slot = last_record.slot

    consensus_speed = (last_slot - first_slot) / (last_timestamp - first_timestamp)

    return consensus_speed


async def _calc_regular_execution_eta(
    execution_client: AsyncWeb3,
    sync_status_history: list[StatusHistoryRecord],
    latest_block: BlockData,
) -> float | None:
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
    execution_eta = (head_slot - latest_block_slot) / execution_speed
    return execution_eta


async def _calc_regular_execution_sync_progress(
    execution_client: AsyncWeb3,
    sync_status_history: list[StatusHistoryRecord],
    latest_block: BlockData,
) -> float:
    """Calculate regular sync progress based on timestamps. Assumes that initial sync is done."""
    latest_ts = latest_block['timestamp']
    head_ts = int(time.time())
    first_block = await execution_client.eth.get_block(sync_status_history[0].block_number)
    first_ts = first_block['timestamp']
    progress = (latest_ts - first_ts) / (head_ts - first_ts)

    return progress


async def _calc_execution_speed_slots(
    sync_status_history: list[StatusHistoryRecord], execution_client: AsyncWeb3
) -> float | None:
    last_record = sync_status_history[-1]
    first_record: StatusHistoryRecord | None = None

    # Too old records are not useful for speed calculation
    max_time_diff = 3600  # 1 hour

    for record in reversed(sync_status_history):
        # Ignore records made while initial sync
        if record.block_number == 0:
            return None

        # Find the last record with a different block number
        # and within the max_time_diff
        if (
            record.block_number != last_record.block_number
            and last_record.timestamp - record.timestamp < max_time_diff
        ):
            first_record = record
            break

    if first_record is None:
        return None

    # Get first and last blocks from the history
    first_block_number = BlockNumber(int(first_record.block_number))
    last_block_number = BlockNumber(int(last_record.block_number))

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

    first_timestamp = int(first_record.timestamp)
    last_timestamp = int(last_record.timestamp)
    execution_speed = (last_block_slot - first_block_slot) / (last_timestamp - first_timestamp)
    return execution_speed


async def _calc_initial_execution_sync_progress(execution_client: AsyncWeb3) -> float:
    """
    Calculate initial sync progress based on syncing stages.
    """
    syncing = await execution_client.eth.syncing
    stages_ready = 0
    stages_total = 0

    for stage in syncing['stages']:  # type: ignore
        if not settings.network_config.NODE_CONFIG.ERA_URL and stage['name'] == 'Era':
            continue

        stages_total += 1

        if stage['block'] != '0x0':
            stages_ready += 1

    if stages_total == 0:
        return 0.0

    return stages_ready / stages_total
