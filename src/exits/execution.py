import logging

from eth_typing import ChecksumAddress, HexStr
from web3 import Web3

from src.common.contracts import keeper_contract
from src.common.transaction import tx_manager
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
        tx_function = keeper_contract.functions.updateExitSignatures(
            vault_address,
            approval.deadline,
            approval.ipfs_hash,
            approval.signatures,
        )
        tx_receipt = await tx_manager.transact(tx_function)

    except Exception as e:
        logger.error('Failed to update exit signatures: %s', format_error(e))

        if settings.verbose:
            logger.exception(e)
        return None

    if tx_receipt is None:
        logger.error('UpdateExitSignatures transaction failed')
        return None
    return Web3.to_hex(tx_receipt['transactionHash'])
