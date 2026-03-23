import logging

from eth_typing import ChecksumAddress, HexStr
from hexbytes import HexBytes
from web3 import Web3

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import NodesManagerContract, NodesManagerEncoder
from src.common.execution import transaction_gas_wrapper
from src.common.typings import HarvestParams
from src.node_manager.typings import OperatorIpfsState, OperatorStateUpdateParams

logger = logging.getLogger(__name__)


async def fetch_operator_state_from_ipfs(
    ipfs_hash: str, operator_address: ChecksumAddress
) -> OperatorStateUpdateParams | None:
    """Fetch operator state data from IPFS and return update params if found."""
    ipfs_data = await ipfs_fetch_client.fetch_json(ipfs_hash)

    for operator_data in ipfs_data.get('operators', []):  # type: ignore
        address = Web3.to_checksum_address(operator_data['address'])
        if address != operator_address:
            continue

        state = OperatorIpfsState(
            address=address,
            total_assets=int(operator_data['totalAssets']),
            cum_penalty_assets=int(operator_data['cumPenaltyAssets']),
            cum_earned_fee_shares=int(operator_data['cumEarnedFeeShares']),
            proof=operator_data['proof'],
        )

        return OperatorStateUpdateParams(
            total_assets=state.total_assets,
            cum_penalty_assets=state.cum_penalty_assets,
            cum_earned_fee_shares=state.cum_earned_fee_shares,
            proof=[HexBytes(Web3.to_bytes(hexstr=HexStr(p))) for p in state.proof],
        )

    return None


async def submit_state_sync_transaction(
    operator_address: ChecksumAddress,
    params: OperatorStateUpdateParams,
    harvest_params: HarvestParams | None = None,
) -> HexStr | None:
    """Submit updateOperatorState, optionally batched with updateVaultState via multicall."""
    nm_contract = NodesManagerContract()
    encoder = NodesManagerEncoder()

    if harvest_params is not None:
        calls: list[HexStr] = [
            encoder.update_vault_state(harvest_params),
            encoder.update_operator_state(operator_address, params),
        ]
        tx_function = nm_contract.contract.functions.multicall(
            [Web3.to_bytes(hexstr=c) for c in calls]
        )
    else:
        tx_function = nm_contract.contract.functions.updateOperatorState(
            operator_address,
            (
                params.total_assets,
                params.cum_penalty_assets,
                params.cum_earned_fee_shares,
                params.proof,
            ),
        )

    tx_hash = await transaction_gas_wrapper(tx_function)
    receipt = await execution_client.eth.wait_for_transaction_receipt(tx_hash)

    if not receipt['status']:
        logger.error('State sync transaction failed: %s', Web3.to_hex(tx_hash))
        return None

    return Web3.to_hex(tx_hash)
