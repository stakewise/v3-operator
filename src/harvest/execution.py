import logging

from eth_typing import ChecksumAddress, HexStr
from sw_utils.networks import GNO_NETWORKS
from web3 import Web3
from web3.exceptions import ContractLogicError, Web3RPCError

from src.common.contracts import (
    get_gno_vault_contract,
    multicall_contract,
    vault_contract,
)
from src.common.transaction import transact_checked
from src.common.typings import HarvestParams
from src.common.utils import warning_verbose
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_harvest_transaction(harvest_params: HarvestParams) -> HexStr | None:
    calls = await get_update_state_calls(harvest_params)
    tx_receipt = await transact_checked(
        multicall_contract.functions.aggregate(calls),
        contract=multicall_contract,
        action='harvest',
    )
    if tx_receipt is None:
        return None

    return Web3.to_hex(tx_receipt['transactionHash'])


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
        except (ValueError, ContractLogicError, Web3RPCError):
            warning_verbose('xDAI swap failed, excluding from the call.')
            calls.pop()

    return [(vault_contract.address, call) for call in calls]
