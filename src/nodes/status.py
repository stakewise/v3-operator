import logging
import time

from eth_typing import BlockNumber
from sw_utils import ExtendedAsyncBeacon
from sw_utils.consensus import ACTIVE_STATUSES, ValidatorStatus
from web3 import AsyncWeb3
from web3.types import BlockData, Timestamp

from src.common.utils import (
    calc_slot_by_block_number,
    calc_slot_by_block_timestamp,
    format_error,
    info_verbose,
    warning_verbose,
)
from src.config.settings import settings
from src.nodes.execution_sync_history import ExecutionSyncHistory
from src.nodes.status_history import SYNC_STATUS_INTERVAL, SyncStatusHistory
from src.nodes.typings import ExecutionSyncRecord, StatusHistoryRecord
from src.validators.keystores.local import LocalKeystore

logger = logging.getLogger(__name__)


async def get_consensus_node_status(consensus_client: ExtendedAsyncBeacon) -> dict:
    try:
        syncing = (await consensus_client.get_syncing())['data']
    except Exception as e:
        warning_verbose('Error fetching consensus node status: %s', format_error(e))
        return {}

    eta = await _calc_consensus_eta(
        consensus_syncing=syncing,
        sync_status_history=SyncStatusHistory().load_history(),
    )
    info_verbose('consensus_eta seconds: %s', int(eta) if eta is not None else 'unavailable')

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
    execution_sync_history = ExecutionSyncHistory().load_history()

    is_initial_sync = latest_block['number'] == 0

    # Assume initial sync is 90% of the total sync process
    initial_sync_ratio = 0.9
    initial_sync_eta = settings.network_config.NODE_CONFIG.INITIAL_SYNC_ETA.total_seconds()
    regular_sync_eta = (1 - initial_sync_ratio) * initial_sync_eta
    eta: float

    if is_initial_sync:
        initial_progress = await _calc_initial_execution_sync_progress(
            execution_client=execution_client
        )
        initial_eta = initial_sync_eta * (1 - initial_progress)
        eta = initial_eta + (1 - initial_sync_ratio) * initial_sync_eta
    elif is_syncing:
        eta = (
            await _calc_regular_execution_eta(
                execution_client=execution_client,
                execution_sync_history=execution_sync_history,
                latest_block=latest_block,
            )
            or regular_sync_eta
        )
    else:
        eta = 0

    return {
        'is_syncing': is_syncing,
        'latest_block_number': latest_block['number'],
        'sync_distance': sync_distance,
        'eta': int(eta),
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

    info_verbose('Fetching validator activity stats...')

    stats['active'] = await _get_number_of_active_validators(
        public_keys=public_keys, consensus_client=consensus_client
    )

    return stats


async def _get_number_of_active_validators(
    public_keys: list[str], consensus_client: ExtendedAsyncBeacon
) -> int:
    if not public_keys:
        return 0

    try:
        validators = (await consensus_client.get_validators_by_ids(public_keys))['data']
    except Exception as e:
        warning_verbose('Error fetching validators: %s', format_error(e))
        return 0

    active_count = 0

    for validator in validators:
        status = ValidatorStatus(validator['status'])
        if status in ACTIVE_STATUSES:
            active_count += 1

    return active_count


async def _calc_consensus_eta(
    consensus_syncing: dict, sync_status_history: list[StatusHistoryRecord]
) -> float | None:
    if len(sync_status_history) < 2:
        info_verbose('Not enough consensus sync status history to calculate ETA.')
        return None

    sync_distance = int(consensus_syncing['sync_distance'])
    allowed_delay = 1

    if sync_distance <= allowed_delay:
        info_verbose('Consensus node is nearly synced. No ETA needed.')
        return 0.0

    consensus_speed = _calc_consensus_speed(sync_status_history)
    default_consensus_speed = 1.0  # Default consensus sync speed in slots/second.
    # This value is chosen because, during sync, nodes typically process slots much faster than the normal slot time (12s/slot).
    # Using 1.0 slots/second is a conservative estimate for sync speed when historical data is unavailable or unreliable.

    if consensus_speed is None:
        info_verbose(
            'Unable to calculate consensus speed from history. Using default value %s.',
            default_consensus_speed,
        )
        consensus_speed = default_consensus_speed

    # If node is synced then calculated consensus_speed can be very low
    # which is not realistic, so we set a minimum threshold
    if consensus_speed < default_consensus_speed:
        info_verbose(
            'Calculated consensus speed %.2f is too low. Using default value %s.',
            consensus_speed,
            default_consensus_speed,
        )
        consensus_speed = default_consensus_speed

    info_verbose('consensus_speed slots/sec: %.2f', consensus_speed)

    return sync_distance / consensus_speed


def _calc_consensus_speed(sync_status_history: list[StatusHistoryRecord]) -> float | None:
    if len(sync_status_history) < 2:
        return None

    first_record = sync_status_history[0]
    last_record = sync_status_history[-1]
    idle_duration = 0

    for i in range(1, len(sync_status_history)):
        curr = sync_status_history[i]
        prev = sync_status_history[i - 1]
        idle_time = max(curr.timestamp - prev.timestamp - SYNC_STATUS_INTERVAL, 0)
        idle_duration += idle_time

    info_verbose('Total idle duration in consensus sync history: %d seconds', int(idle_duration))

    first_timestamp = first_record.timestamp
    last_timestamp = last_record.timestamp

    first_slot = first_record.slot
    last_slot = last_record.slot
    duration = last_timestamp - first_timestamp - idle_duration

    if duration <= 0:
        info_verbose('No valid duration to calculate consensus speed.')
        return None

    consensus_speed = (last_slot - first_slot) / duration

    return consensus_speed


async def _calc_regular_execution_eta(
    execution_client: AsyncWeb3,
    execution_sync_history: list[ExecutionSyncRecord],
    latest_block: BlockData,
) -> float | None:
    if len(execution_sync_history) < 2:
        return None

    latest_block_slot = calc_slot_by_block_timestamp(latest_block['timestamp'])
    cur_ts = int(time.time())
    head_slot = calc_slot_by_block_timestamp(Timestamp(cur_ts))

    execution_speed = await _calc_execution_speed_slots(
        execution_sync_history=execution_sync_history,
        execution_client=execution_client,
    )
    if execution_speed is None or execution_speed <= 0:
        execution_speed = 1.5  # Put reasonable value for a speed

    info_verbose('execution_speed slots/sec: %.2f', execution_speed)

    # Calculate ETA
    execution_eta = (head_slot - latest_block_slot) / execution_speed

    last_record = execution_sync_history[-1] if execution_sync_history else None

    if last_record and last_record.block_number == latest_block['number']:
        execution_eta -= last_record.duration
        execution_eta -= cur_ts - last_record.update_timestamp

    return max(0.0, execution_eta)


async def _calc_execution_speed_slots(
    execution_sync_history: list[ExecutionSyncRecord], execution_client: AsyncWeb3
) -> float | None:
    if len(execution_sync_history) <= 2:
        return None

    # Skip first and last records because they may be incomplete
    first_record = execution_sync_history[1]
    last_record = execution_sync_history[-1]

    # total duration from first to last records
    duration_sum = sum(r.duration for r in execution_sync_history[1:-1])

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

    return (last_block_slot - first_block_slot) / duration_sum


async def _calc_initial_execution_sync_progress(execution_client: AsyncWeb3) -> float:
    return await _calc_initial_execution_sync_progress_using_stages(
        execution_client=execution_client
    )


async def _calc_initial_execution_sync_progress_using_stages(execution_client: AsyncWeb3) -> float:
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
