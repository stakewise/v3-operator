import asyncio
import logging

from eth_typing import HexStr
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress

from src.common.clients import execution_client
from src.common.contracts import multicall_contract
from src.config.settings import VALIDATORS_WITHDRAWALS_CONCURRENCY, settings
from src.eigenlayer.typings import Withdrawal

logger = logging.getLogger(__name__)


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
        asyncio.create_task(fetch_withdrawals(BlockNumber(block_number), indexes, semaphore))
        for block_number in range(from_block, to_block + 1)
    }
    result = []
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            withdrawals = task.result()
            for withdrawal in withdrawals:
                result.append(withdrawal)

    return result


async def fetch_withdrawals(
    block_number: BlockNumber, indexes: set[int], semaphore: asyncio.BoundedSemaphore
) -> list[Withdrawal]:
    """Fetches block withdrawals."""
    async with semaphore:
        block = await execution_client.eth.get_block(block_number)
        withdrawals = []
        for index, withdrawal in enumerate(block.get('withdrawals', [])):
            if int(withdrawal.validatorIndex) in indexes:  # type: ignore[attr-defined]
                withdrawals.append(
                    Withdrawal(
                        block_number=block_number,
                        validator_index=int(
                            withdrawal.validatorIndex  # type: ignore[attr-defined]
                        ),
                        index=index,
                        amount=int(withdrawal.amount),  # type: ignore[attr-defined]
                        withdrawal_address=withdrawal.address,  # type: ignore[attr-defined]
                    )
                )
        return withdrawals
