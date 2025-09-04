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
    consensus_syncing: dict, sync_status_history: list[StatusHistoryRecord]
) -> int | None:
    if len(sync_status_history) < 2:
        return None

    sync_distance = int(consensus_syncing['sync_distance'])
    allowed_delay = 1

    if sync_distance <= allowed_delay:
        return 0

    first_record = sync_status_history[-2]
    last_record = sync_status_history[-1]

    first_timestamp = first_record.timestamp
    last_timestamp = last_record.timestamp

    first_slot = first_record.slot
    last_slot = last_record.slot

    consensus_speed = (last_slot - first_slot) / (last_timestamp - first_timestamp)

    consensus_eta = int(sync_distance / consensus_speed) if consensus_speed > 0 else None
    return consensus_eta


async def _calc_execution_eta(
    execution_client: AsyncWeb3,
    sync_status_history: list[StatusHistoryRecord],
    latest_block: BlockData,
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
    sync_status_history: list[StatusHistoryRecord], execution_client: AsyncWeb3
) -> float | None:
    last_record = sync_status_history[-1]
    first_record: StatusHistoryRecord | None = None

    # Too old records are not useful for speed calculation
    max_time_diff = 3600  # 1 hour

    for record in reversed(sync_status_history):
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
