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
from src.common.typings import ExitQueueMissingAssetsParams, PendingPartialWithdrawal
from src.config.settings import (
    MAX_WITHDRAWAL_BUFFER_GWEI,
    MIN_WITHDRAWAL_BUFFER_GWEI,
    WITHDRAWAL_BUFFER_BPS,
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
    Get the exit queue shortfall and the value of the queued exit shares.
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
    # Queued shares value for the withdrawal buffer. Not needed when nothing is missing.
    total_assets = Wei(0)
    if missing_assets > 0:
        total_assets = await VaultContract(settings.vault).get_queued_exit_assets(
            harvest_params, chain_head.block_number
        )

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
    The cap keeps the buffer from growing with very large queues, the excess would only be
    re-staked.
    """
    buffer = max(total_queue_assets * WITHDRAWAL_BUFFER_BPS // 10_000, MIN_WITHDRAWAL_BUFFER_GWEI)
    return Gwei(min(buffer, MAX_WITHDRAWAL_BUFFER_GWEI))


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
