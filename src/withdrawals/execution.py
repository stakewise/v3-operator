import logging

from eth_typing import HexStr
from web3 import Web3
from web3.types import Gwei

from src.common.clients import execution_client
from src.common.contracts import VaultContract
from src.common.utils import format_error
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_withdraw_validators(
    withdrawals: dict[HexStr, Gwei],
    tx_fee: Gwei,
    validators_manager_signature: HexStr,
) -> HexStr | None:
    """Sends withdrawValidators transaction to vault contract"""
    logger.info('Submitting a withdrawal from validator(s) transaction')
    vault_contract = VaultContract(settings.vault)
    try:
        tx = await vault_contract.functions.withdrawValidators(
            _encode_withdrawals(withdrawals),
            Web3.to_bytes(hexstr=validators_manager_signature),
        ).transact({'value': Web3.to_wei(tx_fee, 'gwei')})
    except Exception as e:
        logger.info('Failed to withdraw from validators: %s', format_error(e))
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.info('Withdraw validators transaction failed')
        return None
    return Web3.to_hex(tx)


def _encode_withdrawals(withdrawals: dict[HexStr, Gwei]) -> bytes:
    """
    Encodes validator data for withdrawValidators contract call
    """
    data = b''
    for public_key, amount in withdrawals.items():
        data += Web3.to_bytes(hexstr=public_key)
        data += amount.to_bytes(8, byteorder='big')

    return data
