import asyncio
import logging
import time
from csv import DictReader, DictWriter
from pathlib import Path

from web3 import AsyncWeb3

from src.config.settings import settings
from src.nodes.typings import ExecutionSyncRecord

logger = logging.getLogger(__name__)


EXECUTION_SYNC_HISTORY_LEN = 100
EXECUTION_SYNC_FIELDNAMES = ['block_number', 'duration', 'update_timestamp']
EXECUTION_SYNC_INTERVAL = 60


class ExecutionSyncHistory:
    def __init__(self) -> None:
        self.last_update_ts: int | None = None

    @property
    def execution_sync_path(self) -> Path:
        return settings.nodes_dir / 'execution_sync.csv'

    async def update_periodically(self, execution_client: AsyncWeb3) -> None:
        """
        Periodically updates the execution synchronization status history of the nodes.
        History is saved to a CSV file.
        """
        # Give the nodes some time to start
        startup_interval = 10
        await asyncio.sleep(startup_interval)

        while True:
            await self._update_sync_status(
                execution_client=execution_client,
            )
            await asyncio.sleep(EXECUTION_SYNC_INTERVAL)

    async def _update_sync_status(self, execution_client: AsyncWeb3) -> None:
        """
        Dumps the synchronization status of the node to a file.
        Save more than one record to be able to see the progress over time.
        Preserve only last EXECUTION_SYNC_HISTORY_LEN records.
        """
        sync_history = self.load_history()

        last_record: ExecutionSyncRecord | None = None

        if sync_history:
            last_record = sync_history[-1]

        cur_ts = int(time.time())
        cur_block_number = await execution_client.eth.block_number

        if not last_record or last_record.block_number != cur_block_number:
            sync_history.append(
                ExecutionSyncRecord(
                    block_number=cur_block_number, duration=0, update_timestamp=cur_ts
                )
            )

        if last_record and self.last_update_ts is not None:
            duration_delta = cur_ts - self.last_update_ts
            last_record.duration += duration_delta

        self.last_update_ts = cur_ts

        if last_record and last_record.block_number == cur_block_number:
            last_record.update_timestamp = cur_ts

        sync_history = sync_history[-EXECUTION_SYNC_HISTORY_LEN:]
        self._dump_history(sync_history)

    def load_history(self, execution_sync_path: Path | None = None) -> list[ExecutionSyncRecord]:
        execution_sync_path = execution_sync_path or self.execution_sync_path

        if not execution_sync_path.exists():
            return []

        records: list[ExecutionSyncRecord] = []

        with execution_sync_path.open('r') as f:
            reader = DictReader(f, fieldnames=EXECUTION_SYNC_FIELDNAMES)
            next(reader)  # skip header
            for row in reader:
                records.append(
                    ExecutionSyncRecord(
                        block_number=int(row['block_number']),
                        duration=int(row['duration']),
                        update_timestamp=int(row['update_timestamp'] or 0),
                    )
                )
        return records

    def _dump_history(self, execution_sync_history: list[ExecutionSyncRecord]) -> None:
        with self.execution_sync_path.open('w') as f:
            writer = DictWriter(f, fieldnames=EXECUTION_SYNC_FIELDNAMES)
            writer.writeheader()
            writer.writerows([record.__dict__ for record in execution_sync_history])
