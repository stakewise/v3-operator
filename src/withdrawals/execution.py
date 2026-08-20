import logging

from eth_typing import HexStr
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.contracts import VaultContract
from src.common.transaction import transact_checked
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_withdraw_validators(
    withdrawals: dict[HexStr, Gwei],
    tx_fee: Wei,
    validators_manager_signature: HexStr,
) -> HexStr | None:
    """Sends withdrawValidators transaction to vault contract"""
    logger.info('Submitting a withdrawal from validator(s) transaction')
    vault_contract = VaultContract(settings.vault)
    tx_function = vault_contract.functions.withdrawValidators(
        _encode_withdrawals(withdrawals),
        Web3.to_bytes(hexstr=validators_manager_signature),
    )
    tx_receipt = await transact_checked(
        tx_function,
        contract=vault_contract,
        action='withdraw from validators',
        tx_params={'value': tx_fee},
    )
    if tx_receipt is None:
        return None
    return Web3.to_hex(tx_receipt['transactionHash'])


def _encode_withdrawals(withdrawals: dict[HexStr, Gwei]) -> bytes:
    """
    Encodes validator data for withdrawValidators contract call
    """
    data = b''
    for public_key, amount in withdrawals.items():
        data += Web3.to_bytes(hexstr=public_key)
        data += amount.to_bytes(8, byteorder='big')

    return data
