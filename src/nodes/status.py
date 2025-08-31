import asyncio
import logging
from csv import DictReader, DictWriter
import time

from src.config.settings import settings

logger = logging.getLogger(__name__)

from src.common.clients import execution_client, consensus_client


SYNC_STATUS_HISTORY_LEN = 2
SYNC_STATUS_FIELDNAMES = ['timestamp', 'block_number', 'slot']
SYNC_STATUS_INTERVAL = 60


async def update_sync_status_periodically() -> None:
    """
    Periodically updates the synchronization status of the node.
    """
    # Give the nodes some time to start
    startup_interval = 10
    await asyncio.sleep(startup_interval)

    while True:
        await _update_sync_status()
        await asyncio.sleep(SYNC_STATUS_INTERVAL)


async def _update_sync_status() -> None:
    """
    Dumps the synchronization status of the node to a file.
    """
    try:
        cur_block_number = await execution_client.eth.block_number
        consensus_syncing = await consensus_client.get_syncing()
    except Exception:
        logger.warning('Nodes are not ready')

    cur_slot = int(consensus_syncing['head_slot'])
    cur_ts = int(time.time())

    sync_status_path = settings.data_dir / 'sync_status.csv'

    with sync_status_path.open('r') as f:
        reader = DictReader(f, fieldnames=SYNC_STATUS_FIELDNAMES)
        sync_status_history = [row for row in reader]

    sync_status_history.append(
        {'timestamp': cur_ts, 'block_number': cur_block_number, 'slot': cur_slot}
    )
    sync_status_history = sync_status_history[-SYNC_STATUS_HISTORY_LEN:]

    with sync_status_path.open('w') as f:
        writer = DictWriter(f, fieldnames=SYNC_STATUS_FIELDNAMES)
        writer.writeheader()
        writer.writerows(sync_status_history)
