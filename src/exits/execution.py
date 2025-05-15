import logging

from eth_typing import ChecksumAddress, HexStr
from web3 import Web3

from src.common.clients import execution_client
from src.common.contracts import keeper_contract
from src.common.typings import OraclesApproval
from src.common.utils import format_error
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_exit_signatures(
    vault_address: ChecksumAddress,
    approval: OraclesApproval,
) -> HexStr | None:
    """Sends updateExitSignatures transaction to keeper contract"""
    logger.info('Submitting UpdateExitSignatures transaction')
    try:
        tx = await keeper_contract.functions.updateExitSignatures(
            vault_address,
            approval.deadline,
            approval.ipfs_hash,
            approval.signatures,
        ).transact()
    except Exception as e:
        logger.error('Failed to update exit signatures: %s', format_error(e))

        if settings.verbose:
            logger.exception(e)
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('UpdateExitSignatures transaction failed')
        return None
    return Web3.to_hex(tx)
