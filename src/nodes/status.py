import asyncio
import logging
import time
from csv import DictReader, DictWriter

from eth_typing import BlockNumber
from sw_utils import ExtendedAsyncBeacon, get_consensus_client, get_execution_client
from web3 import AsyncWeb3
from web3.types import Timestamp

from src.common.utils import calc_slot_by_block_number, calc_slot_by_block_timestamp
from src.config.settings import settings

logger = logging.getLogger(__name__)


SYNC_STATUS_HISTORY_LEN = 10
SYNC_STATUS_FIELDNAMES = ['timestamp', 'block_number', 'slot']
SYNC_STATUS_INTERVAL = 60


async def update_sync_status_periodically() -> None:
    """
    Periodically updates the synchronization status of the node.
    """
    # Create non-retry clients to fail fast
    execution_client = get_execution_client(
        endpoints=settings.execution_endpoints,
        timeout=10,
    )
    consensus_client = get_consensus_client(
        endpoints=settings.consensus_endpoints,
        timeout=10,
    )

    # Give the nodes some time to start
    startup_interval = 10
    await asyncio.sleep(startup_interval)

    while True:
        await _update_sync_status(
            execution_client=execution_client,
            consensus_client=consensus_client,
        )
        await asyncio.sleep(SYNC_STATUS_INTERVAL)


async def calc_sync_eta() -> dict[str, int | None]:
    # Read the sync status history from the file
    sync_status_history = _load_sync_status_history()

    # Create non-retry clients to fail fast
    execution_client = get_execution_client(
        endpoints=settings.execution_endpoints,
        timeout=10,
    )
    consensus_client = get_consensus_client(
        endpoints=settings.consensus_endpoints,
        timeout=10,
    )

    # Calculate ETAs
    execution_eta = await calc_execution_eta(
        execution_client=execution_client,
        sync_status_history=sync_status_history,
    )
    consensus_eta = await calc_consensus_eta(
        consensus_client=consensus_client, sync_status_history=sync_status_history
    )

    return {
        'execution': execution_eta,
        'consensus': consensus_eta,
    }


async def calc_consensus_eta(
    consensus_client: ExtendedAsyncBeacon, sync_status_history: list[dict]
) -> int | None:
    if len(sync_status_history) < 2:
        return None

    first_timestamp = int(sync_status_history[0]['timestamp'])
    last_timestamp = int(sync_status_history[-1]['timestamp'])
    first_slot = int(sync_status_history[0]['slot'])
    last_slot = int(sync_status_history[-1]['slot'])
    consensus_speed = (last_slot - first_slot) / (last_timestamp - first_timestamp)

    try:
        consensus_syncing = (await consensus_client.get_syncing())['data']
    except Exception:
        return None

    sync_distance = int(consensus_syncing['sync_distance'])

    consensus_eta = int(sync_distance / consensus_speed) if consensus_speed > 0 else None
    return consensus_eta


async def calc_execution_eta(
    execution_client: AsyncWeb3,
    sync_status_history: list[dict],
) -> int | None:
    if len(sync_status_history) < 2:
        return None

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

    if execution_speed <= 0:
        return None

    # Get the latest block
    try:
        latest_block = await execution_client.eth.get_block('latest')
    except Exception:
        return None

    # Calculate ETA
    latest_block_slot = calc_slot_by_block_timestamp(latest_block['timestamp'])
    head_slot = calc_slot_by_block_timestamp(Timestamp(int(time.time())))

    allowed_delay = 5
    if latest_block_slot >= head_slot - allowed_delay:
        return 0

    execution_eta = int((head_slot - latest_block_slot) / execution_speed)
    return execution_eta


async def _update_sync_status(
    execution_client: AsyncWeb3, consensus_client: ExtendedAsyncBeacon
) -> None:
    """
    Dumps the synchronization status of the node to a file.
    Save more than one record to be able to see the progress over time.
    Preserve only last SYNC_STATUS_HISTORY_LEN records.
    """

    try:
        cur_block_number = await execution_client.eth.block_number
        consensus_syncing = (await consensus_client.get_syncing())['data']
    except Exception:
        logger.warning('Nodes are not ready, can not update sync status yet')
        return

    cur_slot = int(consensus_syncing['head_slot'])
    cur_ts = int(time.time())

    sync_status_history = _load_sync_status_history()

    sync_status_history.append(
        {'timestamp': cur_ts, 'block_number': cur_block_number, 'slot': cur_slot}
    )
    sync_status_history = sync_status_history[-SYNC_STATUS_HISTORY_LEN:]

    _dump_sync_status_history(sync_status_history)


def _load_sync_status_history() -> list[dict]:
    sync_status_path = settings.data_dir / 'sync_status.csv'

    if sync_status_path.exists():
        with sync_status_path.open('r') as f:
            reader = DictReader(f, fieldnames=SYNC_STATUS_FIELDNAMES)
            next(reader)  # skip header
            return list(reader)

    return []


def _dump_sync_status_history(sync_status_history: list[dict]) -> None:
    sync_status_path = settings.data_dir / 'sync_status.csv'

    with sync_status_path.open('w') as f:
        writer = DictWriter(f, fieldnames=SYNC_STATUS_FIELDNAMES)
        writer.writeheader()
        writer.writerows(sync_status_history)
