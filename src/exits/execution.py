import logging

from web3 import Web3

from src.common.clients import execution_client
from src.common.contracts import keeper_contract
from src.config.networks import ETH_NETWORKS
from src.config.settings import NETWORK, VAULT_CONTRACT_ADDRESS
from src.exits.typings import OraclesApproval, UpdateExitSignaturesParams

logger = logging.getLogger(__name__)


async def register_exit_signatures(
    approval: OraclesApproval,
) -> None:
    """Sends updateExitSignatures transaction to keeper contract"""
    if NETWORK not in ETH_NETWORKS:
        raise NotImplementedError('networks other than Ethereum not supported')

    tx_data = UpdateExitSignaturesParams(
        vault=VAULT_CONTRACT_ADDRESS,
        exitSignaturesIpfsHash=approval.ipfs_hash,
        oraclesSignatures=approval.signatures,
    )

    logger.info('Submitting UpdateExitSignatures transaction')
    tx = await keeper_contract.functions.updateExitSignatures(
        tx_data.vault,
        tx_data.exitSignaturesIpfsHash,
        tx_data.oraclesSignatures,
    ).transact()  # type: ignore
    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    await execution_client.eth.wait_for_transaction_receipt(tx, timeout=300)  # type: ignore
