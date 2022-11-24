import datetime
import logging
import time

from tqdm import tqdm
from web3 import Web3
from web3._utils.events import EventData

from src.common.database import Database
from src.config.settings import NETWORK_CONFIG

from .contracts import get_deposit_contract
from .event_scanner import EventScanner, EventScannerState
from .execution import LightExecutionClient

logger = logging.getLogger(__name__)


class DatabaseState(EventScannerState):
    """Store the state of scanned blocks and all events."""

    def __init__(self, database: Database):
        self.database = database
        self.last_scanned_block = 0

    def get_last_scanned_block(self):
        """The number of the last block we have stored."""
        return self.last_scanned_block

    def delete_data(self, since_block):
        """Remove potentially reorganised blocks from the scan data."""
        self.database.delete_deposit_events(since_block)

    def start_chunk(self, block_number, chunk_size):
        pass

    def end_chunk(self, block_number):
        """Save at the end of each block, so we can resume in the case of a crash or CTRL+C"""
        # Next time the scanner is started we will resume from this block
        self.last_scanned_block = block_number
        self.database.save_block(block_number)

    def process_event(self, block_when: datetime.datetime, event: EventData) -> str:
        """Record a ERC-20 transfer in our database."""
        # Events are keyed by their transaction hash and log index
        # One transaction may contain multiple events
        # and each one of those gets their own log index

        # event_name = event.event # "Transfer"
        log_index = event.logIndex  # Log index within the block
        # transaction_index = event.transactionIndex  # Transaction index within the block
        txhash = event.transactionHash.hex()  # Transaction hash
        block_number = event.blockNumber

        self.database.create_deposit_event(
            public_key=Web3.to_hex(primitive=event['args']['pubkey']),
            signature=Web3.to_hex(primitive=event['args']['signature']),
            index=Web3.to_int(primitive=event['args']['index']),
            block_number=block_number,
            log_index=log_index,
            transaction_hash=txhash,
        )

        # Return a pointer that allows us to look up this event later if needed
        return f'{block_number}-{txhash}-{log_index}'


class DepositEventsScanner:
    def sync(self, database, genesis_block=1):
        contract = get_deposit_contract()

        # Restore/create our persistent state
        state = DatabaseState(database)

        scanner = EventScanner(
            w3=LightExecutionClient().get_client(),
            contract=contract,
            state=state,
            genesis_block=genesis_block,
            events=[contract.events.DepositEvent],
            filters={'address': NETWORK_CONFIG.DEPOSIT_CONTRACT_ADDRESS},
            # How many maximum blocks at the time we request from JSON-RPC
            # and we are unlikely to exceed the response size limit of the JSON-RPC server
            max_chunk_scan_size=10000,
        )

        # Assume we might have scanned the blocks all the way to the last Ethereum block
        # that mined a few seconds before the previous scan run ended.
        # Because there might have been a minor Etherueum chain reorganisations
        # since the last scan ended, we need to discard
        # the last few blocks from the previous scan results.
        chain_reorg_safety_blocks = 10
        scanner.delete_potentially_forked_block_data(
            state.get_last_scanned_block() - chain_reorg_safety_blocks
        )

        # Scan from [last block scanned] - [latest ethereum block]
        # Note that our chain reorg safety blocks cannot go negative
        start_block = max(scanner.get_suggested_scan_start_block() - chain_reorg_safety_blocks, 0)
        end_block = scanner.get_suggested_scan_end_block()
        blocks_to_scan = end_block - start_block

        logger.info(f'Scanning events from blocks {start_block} - {end_block}')

        # Render a progress bar in the console
        start = time.time()
        with tqdm(total=blocks_to_scan) as progress_bar:

            def _update_progress(
                start, end, current, current_block_timestamp, chunk_size, events_count
            ):
                if current_block_timestamp:
                    formatted_time = current_block_timestamp.strftime('%d-%m-%Y')
                else:
                    formatted_time = 'no block time available'
                progress_bar.set_description(
                    f'Current block: {current} ({formatted_time}), blocks in a scan batch: {chunk_size},'
                    f' events processed in a batch {events_count}'
                )
                progress_bar.update(chunk_size)

            # Run the scan
            result, total_chunks_scanned = scanner.scan(
                start_block, end_block, progress_callback=_update_progress
            )

        duration = time.time() - start
        logger.info(
            f'Scanned total {len(result)} events, in {duration} seconds,'
            f' total {total_chunks_scanned} chunk scans performed'
        )
