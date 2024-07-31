import asyncio
import logging

from eth_typing import HexStr
from web3 import Web3
from web3.exceptions import ContractLogicError
from web3.types import BlockNumber, ChecksumAddress

from src.common.clients import execution_client
from src.common.contracts import EigenPodOwnerContract, multicall_contract
from src.common.utils import format_error, log_verbose
from src.config.settings import EIGEN_VALIDATORS_WITHDRAWALS_CONCURRENCY, settings
from src.eigenlayer.typings import Withdrawal

logger = logging.getLogger(__name__)


async def submit_multicall_transaction(
    calls: list[tuple[ChecksumAddress, HexStr]]
) -> HexStr | None:
    try:
        tx = await multicall_contract.functions.aggregate(calls).transact()
    except (ValueError, ContractLogicError) as e:
        logger.error('Failed to process withdrawal: %s', format_error(e))
        if settings.verbose:
            log_verbose(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for transaction %s confirmation', tx_hash)

    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Multicall transaction failed')
        return None
    return tx_hash


# pylint: disable-next=too-many-arguments
async def submit_verify_withdrawal_credentials_transaction(
    pod_owner: ChecksumAddress,
    oracle_timestamp: int,
    state_root_proof: tuple[bytes, bytes],
    validator_indices: list[int],
    validator_fields_proofs: list[bytes],
    validator_fields: list[list[bytes]],
) -> HexStr | None:
    """Sends verifyWithdrawalCredentials transaction to pod owner contract"""
    logger.info('Submitting verify withdrawal credentials transaction')
    try:
        tx = (
            await EigenPodOwnerContract(pod_owner)
            .functions.verifyWithdrawalCredentials(
                oracle_timestamp,
                state_root_proof,
                validator_indices,
                validator_fields_proofs,
                validator_fields,
            )
            .transact()
        )
    except Exception as e:
        logger.error('Failed to verify withdrawal credentials: %s', format_error(e))

        if settings.verbose:
            log_verbose(e)
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('verify withdrawal credentials transaction failed')
        return None
    return Web3.to_hex(tx)


async def submit_queue_withdrawal_transaction(
    pod_owner: ChecksumAddress,
    shares: int,
) -> HexStr | None:
    """Sends queueWithdrawal transaction to pod owner contract"""
    logger.info('Submitting queue withdrawal transaction')
    try:
        tx = (
            await EigenPodOwnerContract(pod_owner)
            .functions.queueWithdrawal(
                shares,
            )
            .transact()
        )
    except Exception as e:
        logger.error('Failed to queue withdrawal: %s', format_error(e))

        if settings.verbose:
            log_verbose(e)
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('queue withdrawal transaction failed')
        return None
    return Web3.to_hex(tx)


# pylint: disable-next=too-many-arguments
async def submit_complete_queued_withdrawal_transaction(
    pod_owner: ChecksumAddress,
    delegated_to: ChecksumAddress,
    nonce: int,
    shares: int,
    start_block: BlockNumber,
    receive_as_tokens: bool,
) -> HexStr | None:
    """Sends completeQueuedWithdrawal transaction to pod owner contract"""
    logger.info('Submitting complete queued withdrawal transaction')

    middleware_times_index = (
        0  # middlewareTimesIndex is unused, but will be used in the Slasher eventually
    )
    try:
        tx = (
            await EigenPodOwnerContract(pod_owner)
            .functions.completeQueuedWithdrawal(
                delegated_to,
                nonce,
                shares,
                start_block,
                middleware_times_index,
                receive_as_tokens,
            )
            .transact()
        )
    except Exception as e:
        logger.error('Failed to complete queued withdrawal: %s', format_error(e))

        if settings.verbose:
            log_verbose(e)
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('complete queued withdrawal transaction failed')
        return None
    return Web3.to_hex(tx)


async def get_validator_withdrawals_chunk(
    indexes: set[int], from_block: BlockNumber, to_block: BlockNumber
) -> list[Withdrawal]:
    semaphore = asyncio.BoundedSemaphore(EIGEN_VALIDATORS_WITHDRAWALS_CONCURRENCY)
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
            if int(withdrawal['validator_index']) in indexes:
                withdrawals.append(
                    Withdrawal(
                        block_number=block_number,
                        validator_index=withdrawal['validator_index'],
                        index=index,
                        amount=withdrawal['amount'],
                        withdrawal_address=withdrawal['address'],
                    )
                )
        return withdrawals
