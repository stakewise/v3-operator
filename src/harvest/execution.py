import logging

from eth_typing import ChecksumAddress, HexStr
from sw_utils.networks import GNO_NETWORKS
from web3 import Web3
from web3.exceptions import ContractLogicError

from src.common.clients import execution_client
from src.common.contracts import GnoVaultContract, VaultContract, multicall_contract
from src.common.execution import transaction_gas_wrapper
from src.common.typings import HarvestParams
from src.common.utils import format_error, warning_verbose
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_harvest_transaction(
    vault_address: ChecksumAddress, harvest_params: HarvestParams
) -> HexStr | None:
    calls = await get_update_state_calls(harvest_params=harvest_params, vault_address=vault_address)
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


async def get_update_state_calls(
    vault_address: ChecksumAddress,
    harvest_params: HarvestParams,
) -> list[tuple[ChecksumAddress, HexStr]]:
    vault_contract = VaultContract(vault_address)
    update_state_call = vault_contract.get_update_state_call(harvest_params)
    calls = [update_state_call]

    if settings.network in GNO_NETWORKS:
        gno_vault_contract = GnoVaultContract(vault_address)
        swap_xdai_call = gno_vault_contract.get_swap_xdai_call()
        calls.append(swap_xdai_call)

        # check whether xDAI swap works
        try:
            await gno_vault_contract.functions.multicall(calls).call()
        except (ValueError, ContractLogicError):
            warning_verbose('xDAI swap failed, excluding from the call.')
            calls.pop()

    return [(vault_contract.contract_address, call) for call in calls]
