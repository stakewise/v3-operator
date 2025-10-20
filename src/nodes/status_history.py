import asyncio
import logging
import time
from csv import DictReader, DictWriter
from pathlib import Path

from sw_utils import ExtendedAsyncBeacon
from web3 import AsyncWeb3

from src.config.settings import settings
from src.nodes.typings import StatusHistoryRecord

logger = logging.getLogger(__name__)


SYNC_STATUS_HISTORY_LEN = 100
SYNC_STATUS_FIELDNAMES = ['timestamp', 'block_number', 'slot']
SYNC_STATUS_INTERVAL = 60


class SyncStatusHistory:
    async def update_periodically(
        self, execution_client: AsyncWeb3, consensus_client: ExtendedAsyncBeacon
    ) -> None:
        """
        Periodically updates the synchronization status history of the nodes.
        History is saved to a CSV file.
        """
        # Give the nodes some time to start
        startup_interval = 10
        await asyncio.sleep(startup_interval)

        while True:
            try:
                await self._update_sync_status(
                    execution_client=execution_client,
                    consensus_client=consensus_client,
                )
            except Exception as e:
                logger.error('Error updating sync status: %s', e)
            await asyncio.sleep(SYNC_STATUS_INTERVAL)

    async def _update_sync_status(
        self, execution_client: AsyncWeb3, consensus_client: ExtendedAsyncBeacon
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

        sync_status_history = SyncStatusHistory().load_history()

        sync_status_history.append(
            StatusHistoryRecord(timestamp=cur_ts, block_number=cur_block_number, slot=cur_slot)
        )
        sync_status_history = sync_status_history[-SYNC_STATUS_HISTORY_LEN:]

        self._dump_history(sync_status_history)

    def load_history(self, sync_status_path: Path | None = None) -> list[StatusHistoryRecord]:
        sync_status_path = sync_status_path or (settings.nodes_dir / 'sync_status.csv')

        if not sync_status_path.exists():
            return []

        records: list[StatusHistoryRecord] = []

        with sync_status_path.open('r') as f:
            reader = DictReader(f, fieldnames=SYNC_STATUS_FIELDNAMES)
            next(reader)  # skip header
            for row in reader:
                records.append(
                    StatusHistoryRecord(
                        timestamp=int(row['timestamp']),
                        block_number=int(row['block_number']),
                        slot=int(row['slot']),
                    )
                )
        return records

    def _dump_history(self, sync_status_history: list[StatusHistoryRecord]) -> None:
        sync_status_path = settings.nodes_dir / 'sync_status.csv'

        with sync_status_path.open('w') as f:
            writer = DictWriter(f, fieldnames=SYNC_STATUS_FIELDNAMES)
            writer.writeheader()
            writer.writerows([record.__dict__ for record in sync_status_history])
