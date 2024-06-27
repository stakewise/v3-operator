import asyncio
import logging

from eth_typing import HexStr
from sw_utils import EventProcessor
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, EventData

from src.common.clients import execution_client
from src.common.contracts import multicall_contract
from src.common.eigenlayer_contracts import delegation_manager_contract
from src.config.settings import VALIDATORS_WITHDRAWALS_CONCURRENCY, settings
from src.eigenlayer.typings import Withdrawal

logger = logging.getLogger(__name__)


class WithdrawalQueuedProcessor(EventProcessor):
    contract_event = 'WithdrawalQueued'

    @property
    def contract(self):
        return delegation_manager_contract

    @staticmethod
    async def get_from_block() -> BlockNumber:
        last_validator = NetworkValidatorCrud().get_last_network_validator()
        if not last_validator:
            return settings.network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK

        return BlockNumber(last_validator.block_number + 1)

    @staticmethod
    # pylint: disable-next=unused-argument
    async def process_events(events: list[EventData], to_block: BlockNumber) -> None:
        NetworkValidatorCrud().save_network_validators(validators)


# last processed block
# last unprocessed block
# last scanned block


async def submit_multicall_transaction(
    calls: list[tuple[ChecksumAddress, bool, HexStr]]
) -> HexStr | None:
    tx = await multicall_contract.functions.aggregate(calls).transact()

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for transaction %s confirmation', tx_hash)

    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('RRRRRR transaction failed')
        return None
    return tx_hash


async def get_validator_withdrawals_chunk(
    indexes: set[int], from_block: BlockNumber, to_block: BlockNumber
) -> list[Withdrawal]:
    semaphore = asyncio.BoundedSemaphore(VALIDATORS_WITHDRAWALS_CONCURRENCY)
    pending = {
        asyncio.create_task(fetch_withdrawals(BlockNumber(block_number), semaphore))
        for block_number in range(from_block, to_block + 1)
    }
    result = []
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            withdrawals = task.result()
            for withdrawal in withdrawals:
                if withdrawal.validator_index in indexes:  # todo: check in fetch_withdrawals?
                    result.append(withdrawal)

    return result


async def fetch_withdrawals(
    block_number: BlockNumber, semaphore: asyncio.BoundedSemaphore
) -> list[Withdrawal]:
    """Fetches block withdrawals."""
    async with semaphore:
        block = await execution_client.eth.get_block(block_number)
        '''
      block_number: BlockNumber
      validator_index: BlockNumber
      amount: int  # gwei
      index: int
      withdrawal_address: ChecksumAddress
      '''
        return [
            Withdrawal(
                block_number=block_number,
                validator_index=int(withdrawal.validatorIndex),
                index=int(withdrawal.index),
                amount=int(withdrawal.amount),
                withdrawal_address=withdrawal.address,
            )
            for withdrawal in block.get('withdrawals', [])
        ]
