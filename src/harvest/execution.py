import logging

from eth_typing import HexStr
from web3 import Web3
from web3.exceptions import ContractLogicError

from src.common.clients import execution_client
from src.common.contracts import VaultContract, multicall_contract
from src.common.execution import transaction_gas_wrapper
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
        tx = await transaction_gas_wrapper(tx_function=tx_function)
        tx_hash = Web3.to_hex(tx)
    except (ValueError, ContractLogicError) as e:
        logger.error('Failed to harvest: %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx_hash, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Harvest transaction failed')
        return None

    return tx_hash
