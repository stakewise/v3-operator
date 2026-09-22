from typing import cast

from sw_utils import (
    GNO_NETWORKS,
    ChainHead,
    ValidatorStatus,
    convert_to_gno,
    convert_to_mgno,
)
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.contracts import VaultContract, validators_checker_contract
from src.common.harvest import get_harvest_params
from src.common.typings import (
    ExitQueueMissingAssetsParams,
    ExitQueueState,
    PendingPartialWithdrawal,
)
from src.config.settings import (
    MIN_WITHDRAWAL_BUFFER_GWEI,
    WITHDRAWAL_BUFFER_RATIO_DIVISOR,
    settings,
)
from src.validators.typings import ConsensusValidator, ValidatorConsolidationData
from src.withdrawals.typings import ExitQueueAssets

EXITING_STATUSES = [
    ValidatorStatus.ACTIVE_EXITING,
    ValidatorStatus.ACTIVE_SLASHED,
    ValidatorStatus.EXITED_UNSLASHED,
    ValidatorStatus.EXITED_SLASHED,
    ValidatorStatus.WITHDRAWAL_POSSIBLE,
]


# pylint: disable-next=too-many-arguments
async def get_queued_assets(
    consensus_validators: list[ConsensusValidator],
    oracle_exiting_validators: list[ConsensusValidator],
    pending_partial_withdrawals: list[PendingPartialWithdrawal],
    chain_head: ChainHead,
    redemption_assets: Wei,
) -> ExitQueueAssets:
    """
    Get the exit queue shortfall and the whole exit queue value.
    For Gno networks both are in mGNO-Gwei.
    """
    harvest_params = await get_harvest_params(settings.vault, chain_head.block_number)

    # Get exit queue cumulative tickets
    exit_queue_cumulative_ticket = (
        await validators_checker_contract.get_exit_queue_cumulative_tickets(
            vault_address=settings.vault,
            harvest_params=harvest_params,
            block_number=chain_head.block_number,
        )
    )
    pending_partial_withdrawals_amount_gwei = sum(
        withdrawal.amount for withdrawal in pending_partial_withdrawals
    )
    pending_partial_withdrawals_amount = Web3.to_wei(
        pending_partial_withdrawals_amount_gwei, 'gwei'
    )

    # fetch active validators exits
    validators_exits_amount = _calculate_validators_exits_amount(
        consensus_validators=consensus_validators,
        oracle_exiting_validators=oracle_exiting_validators,
    )

    # Withdrawing assets are assets that are ready to cover the exit requests
    # but not yet used to fulfill exit requests.
    withdrawing_assets = Wei(pending_partial_withdrawals_amount + validators_exits_amount)
    if settings.network in GNO_NETWORKS:
        # apply mGNO -> GNO exchange rate
        withdrawing_assets = convert_to_gno(withdrawing_assets)

    # Missing assets express how much assets are needed to cover the exit requests
    # until the exit queue cumulative ticket is reached
    missing_assets = await validators_checker_contract.get_exit_queue_missing_assets(
        exit_queue_missing_assets_params=ExitQueueMissingAssetsParams(
            vault=settings.vault,
            withdrawing_assets=withdrawing_assets,
            redemption_assets=redemption_assets,
            exit_queue_cumulative_ticket=exit_queue_cumulative_ticket,
        ),
        harvest_params=harvest_params,
        block_number=chain_head.block_number,
    )
    # Whole queue value for the withdrawal buffer. Not needed when nothing is missing.
    total_assets = Wei(0)
    if missing_assets > 0:
        state = await VaultContract(settings.vault).get_exit_queue_state(
            harvest_params, chain_head.block_number
        )
        total_assets = _calculate_exit_queue_assets(state, exit_queue_cumulative_ticket)

    if settings.network in GNO_NETWORKS:
        # apply GNO -> mGNO exchange rate
        missing_assets = convert_to_mgno(missing_assets)
        total_assets = convert_to_mgno(total_assets)

    return ExitQueueAssets(
        missing=Gwei(int(Web3.from_wei(missing_assets, 'gwei'))),
        total=Gwei(int(Web3.from_wei(total_assets, 'gwei'))),
    )


def calculate_withdrawal_buffer(total_queue_assets: Gwei) -> Gwei:
    """
    Queued assets keep accruing rewards while the withdrawal is pending on the consensus layer
    (about 27h for a partial withdrawal, up to ~11 days for a full exit), so requesting the
    exact shortfall leaves a new tiny one after every reward update. 0.1% of the queue covers
    about 18 days of rewards at 2% APR; the floor covers queues too small for the ratio.
    """
    buffer = max(total_queue_assets // WITHDRAWAL_BUFFER_RATIO_DIVISOR, MIN_WITHDRAWAL_BUFFER_GWEI)
    return Gwei(buffer)


def _calculate_validators_exits_amount(
    consensus_validators: list[ConsensusValidator],
    oracle_exiting_validators: list[ConsensusValidator],
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

    for val in consensus_validators:
        consolidation_data = cast(ValidatorConsolidationData, val.consolidation_data)
        if consolidation_data.is_source or val.index in oracle_exiting_indexes:
            continue
        if val.status in EXITING_STATUSES:
            total_exiting_amount += val.balance

    return Web3.to_wei(total_exiting_amount, 'gwei')


def _calculate_exit_queue_assets(state: ExitQueueState, exit_queue_cumulative_ticket: int) -> Wei:
    """
    Mirrors ``ValidatorsChecker.getExitQueueMissingAssets`` with ``redemptionAssets = 0`` and
    without subtracting the vault's available balance: the withdrawal buffer must cover rewards
    accruing on the whole queue, including the part the vault's own balance already covers.
    """
    total_tickets_to_cover = max(0, exit_queue_cumulative_ticket - state.total_tickets)

    assets = 0
    if state.total_exiting_tickets > 0:
        legacy_tickets_to_cover = min(total_tickets_to_cover, state.total_exiting_tickets)
        assets += (
            legacy_tickets_to_cover * state.total_exiting_assets // state.total_exiting_tickets
        )
        total_tickets_to_cover -= legacy_tickets_to_cover

    if total_tickets_to_cover > 0 and state.queued_shares > 0:
        shares_to_cover = min(total_tickets_to_cover, state.queued_shares)
        if state.total_shares == 0:
            assets += shares_to_cover
        else:
            assets += shares_to_cover * state.total_assets // state.total_shares

    return Wei(assets)
