import logging

from eth_typing import HexStr
from web3 import Web3
from web3.exceptions import ContractLogicError

from src.common.contracts import VaultContract, multicall_contract
from src.common.transaction import tx_manager
from src.common.typings import HarvestParams
from src.common.utils import format_error
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_harvest_transaction(harvest_params: HarvestParams) -> HexStr | None:
    vault_contract = VaultContract(settings.vault)
    calls = [
        (vault_contract.contract_address, vault_contract.get_update_state_call(harvest_params))
    ]
    try:
        tx_function = multicall_contract.functions.aggregate(calls)
        tx_receipt = await tx_manager.transact(tx_function)
    except (ValueError, ContractLogicError) as e:
        logger.error('Failed to harvest: %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    if tx_receipt is None:
        logger.error('Harvest transaction failed')
        return None

    return Web3.to_hex(tx_receipt['transactionHash'])
