import logging

from eth_typing import ChecksumAddress, HexStr
from web3 import Web3

from src.common.contracts import keeper_contract
from src.common.transaction import transact_checked
from src.common.typings import OraclesApproval

logger = logging.getLogger(__name__)


async def submit_exit_signatures(
    vault_address: ChecksumAddress,
    approval: OraclesApproval,
) -> HexStr | None:
    """Sends updateExitSignatures transaction to keeper contract"""
    logger.info('Submitting UpdateExitSignatures transaction')
    tx_function = keeper_contract.functions.updateExitSignatures(
        vault_address,
        approval.deadline,
        approval.ipfs_hash,
        approval.signatures,
    )
    tx_receipt = await transact_checked(
        tx_function,
        contract=keeper_contract,
        action='update exit signatures',
    )
    if tx_receipt is None:
        return None
    return Web3.to_hex(tx_receipt['transactionHash'])
