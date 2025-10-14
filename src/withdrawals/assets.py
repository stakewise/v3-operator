from sw_utils import (
    GNO_NETWORKS,
    ChainHead,
    ValidatorStatus,
    convert_to_gno,
    convert_to_mgno,
)
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.contracts import validators_checker_contract
from src.common.execution import (
    get_pending_consolidations,
    get_pending_partial_withdrawals,
)
from src.common.harvest import get_harvest_params
from src.common.typings import ExitQueueMissingAssetsParams
from src.config.settings import settings
from src.validators.typings import ConsensusValidator

CAN_BE_EXITED_STATUSES = [
    ValidatorStatus.ACTIVE_ONGOING,
    ValidatorStatus.ACTIVE_EXITING,
    ValidatorStatus.ACTIVE_SLASHED,
    ValidatorStatus.EXITED_UNSLASHED,
    ValidatorStatus.EXITED_SLASHED,
    ValidatorStatus.WITHDRAWAL_POSSIBLE,
]


EXITING_STATUSES = [
    ValidatorStatus.ACTIVE_EXITING,
    ValidatorStatus.ACTIVE_SLASHED,
    ValidatorStatus.EXITED_UNSLASHED,
    ValidatorStatus.EXITED_SLASHED,
    ValidatorStatus.WITHDRAWAL_POSSIBLE,
]


async def get_queued_assets(
    consensus_validators: list[ConsensusValidator],
    oracle_exiting_validators: list[ConsensusValidator],
    chain_head: ChainHead,
) -> Gwei:
    harvest_params = await get_harvest_params(chain_head.block_number)

    # Get exit queue cumulative tickets
    exit_queue_cumulative_ticket = (
        await validators_checker_contract.get_exit_queue_cumulative_tickets(
            vault_address=settings.vault,
            harvest_params=harvest_params,
            block_number=chain_head.block_number,
        )
    )
    # fetch current pending partial withdrawals from consensus client
    pending_partial_withdrawals_amount = await _get_pending_partial_withdrawals_amount(
        validators=[v for v in consensus_validators if v.status in CAN_BE_EXITED_STATUSES],
        chain_head=chain_head,
    )
    # fetch active validators exits
    consolidations = await get_pending_consolidations(chain_head, consensus_validators)
    source_consolidations_indexes = {cons.source_index for cons in consolidations}
    validators_exits_amount = _calculate_validators_exits_amount(
        consensus_validators=consensus_validators,
        oracle_exiting_validators=oracle_exiting_validators,
        source_consolidations_indexes=source_consolidations_indexes,
    )

    # Withdrawing assets are assets that are ready to cover the exit requests
    # but not yet used to fulfill exit requests.
    withdrawing_assets = Wei(pending_partial_withdrawals_amount + validators_exits_amount)
    if settings.network in GNO_NETWORKS:
        # apply mGNO -> GNO exchange rate
        withdrawing_assets = convert_to_gno(withdrawing_assets)
    # Missing assets express how much assets are needed to cover the exit requests
    # until the exit queue cumulative ticket is reached
    queued_assets = await validators_checker_contract.get_exit_queue_missing_assets(
        exit_queue_missing_assets_params=ExitQueueMissingAssetsParams(
            vault=settings.vault,
            withdrawing_assets=withdrawing_assets,
            exit_queue_cumulative_ticket=exit_queue_cumulative_ticket,
        ),
        harvest_params=harvest_params,
        block_number=chain_head.block_number,
    )

    if settings.network in GNO_NETWORKS:
        # apply GNO -> mGNO exchange rate
        queued_assets = convert_to_mgno(queued_assets)

    return Gwei(int(Web3.from_wei(queued_assets, 'gwei')))


async def _get_pending_partial_withdrawals_amount(
    validators: list[ConsensusValidator],
    chain_head: ChainHead,
) -> Wei:
    """
    Calculate the sum of pending partial withdrawals at the specified slot
    """
    if not validators:
        return Wei(0)

    total_pending_withdrawals = 0
    pending_withdrawals = await get_pending_partial_withdrawals(chain_head, validators)
    for pending_withdrawal in pending_withdrawals:
        total_pending_withdrawals += pending_withdrawal.amount

    return Web3.to_wei(total_pending_withdrawals, 'gwei')


def _calculate_validators_exits_amount(
    consensus_validators: list[ConsensusValidator],
    oracle_exiting_validators: list[ConsensusValidator],
    source_consolidations_indexes: set[int],
) -> Wei:
    """
    Calculate the sum of exiting validators balances. Exiting validators are:
    1) Validators with exiting status
    2) Validators that are in active exits according to oracles
    3) Exclude validators that are consolidating
    """
    oracle_exiting_indexes = set()
    total_exiting_amount = 0
    for val in oracle_exiting_validators:
        if val.index in oracle_exiting_indexes:
            continue
        oracle_exiting_indexes.add(val.index)
        total_exiting_amount += val.balance

    excluded_indexes = source_consolidations_indexes.union(oracle_exiting_indexes)
    for val in consensus_validators:
        if val.index not in excluded_indexes and val.status in EXITING_STATUSES:
            total_exiting_amount += val.balance

    return Web3.to_wei(total_exiting_amount, 'gwei')
