import asyncio
import logging

from eth_typing import ChecksumAddress, HexStr
from hexbytes import HexBytes
from sw_utils.networks import GNO_NETWORKS
from web3 import Web3
from web3.contract.async_contract import AsyncContractFunction
from web3.exceptions import ContractLogicError
from web3.types import TxParams

from src.common.clients import execution_client
from src.common.contracts import (
    get_gno_vault_contract,
    multicall_contract,
    vault_contract,
)
from src.common.execution import build_gas_manager
from src.common.typings import HarvestParams
from src.common.utils import format_error, warning_verbose
from src.config.settings import ATTEMPTS_WITH_DEFAULT_GAS, settings

logger = logging.getLogger(__name__)


async def submit_harvest_transaction(harvest_params: HarvestParams) -> HexStr | None:
    calls = await get_update_state_calls(harvest_params)
    try:
        tx_function = multicall_contract.functions.aggregate(calls)
        tx = await _transaction_gas_wrapper(tx_function=tx_function)
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
    harvest_params: HarvestParams,
) -> list[tuple[ChecksumAddress, HexStr]]:
    update_state_call = vault_contract.get_update_state_call(harvest_params)
    calls = [update_state_call]

    if settings.network in GNO_NETWORKS:
        gno_vault_contract = get_gno_vault_contract()
        swap_xdai_call = gno_vault_contract.get_swap_xdai_call()
        calls.append(swap_xdai_call)

        # check whether xDAI swap works
        try:
            await gno_vault_contract.functions.multicall(calls).call()
        except (ValueError, ContractLogicError):
            warning_verbose('xDAI swap failed, excluding from the call.')
            calls.pop()

    return [(vault_contract.address, call) for call in calls]


async def _transaction_gas_wrapper(
    tx_function: AsyncContractFunction, tx_params: TxParams | None = None
) -> HexBytes:
    """Handles periods with high gas in the network."""
    if not tx_params:
        tx_params = {}

    # trying to submit with basic gas
    for i in range(ATTEMPTS_WITH_DEFAULT_GAS):
        try:
            return await tx_function.transact(tx_params)
        except ValueError as e:
            # Handle only FeeTooLow error
            code = None
            if e.args and isinstance(e.args[0], dict):
                code = e.args[0].get('code')
            if not code or code != -32010:
                raise e
            if i < ATTEMPTS_WITH_DEFAULT_GAS - 1:  # skip last sleep
                await asyncio.sleep(settings.network_config.SECONDS_PER_BLOCK)

    # use high priority fee
    gas_manager = build_gas_manager()
    tx_params = tx_params | await gas_manager.get_high_priority_tx_params()
    return await tx_function.transact(tx_params)
