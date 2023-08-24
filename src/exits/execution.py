import logging

from eth_typing import HexStr
from web3 import Web3

from src.common.clients import execution_client
from src.common.contracts import keeper_contract
from src.config.networks import ETH_NETWORKS
from src.config.settings import settings
from src.exits.typings import OraclesApproval

logger = logging.getLogger(__name__)


async def submit_exit_signatures(
    approval: OraclesApproval,
) -> HexStr:
    """Sends updateExitSignatures transaction to keeper contract"""
    if settings.network not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    logger.info('Submitting UpdateExitSignatures transaction')
    tx = await keeper_contract.functions.updateExitSignatures(
        settings.vault, approval.ipfs_hash, approval.signatures, int(approval.deadline.timestamp())
    ).transact()
    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)
    return Web3.to_hex(tx)
