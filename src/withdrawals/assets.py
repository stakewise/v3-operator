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

from src.common.contracts import validators_checker_contract
from src.common.harvest import get_harvest_params
from src.common.typings import ExitQueueMissingAssetsParams, PendingPartialWithdrawal
from src.config.networks import NetworkConfig
from src.config.settings import WITHDRAWAL_BUFFER_SAFETY_FACTOR, settings
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
    Get the exit queue's missing assets (the net shortfall that must be requested now) and
    total assets (the whole remaining queue, used by `calculate_withdrawal_buffer`).
    For Gno networks both are returned in mGNO-Gwei.
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
    # Total assets still in the queue after the simulated harvest: the whole
    # share-denominated base that keeps accruing rewards, see calculate_withdrawal_buffer.
    total_assets = await validators_checker_contract.get_exit_queue_missing_assets(
        exit_queue_missing_assets_params=ExitQueueMissingAssetsParams(
            vault=settings.vault,
            withdrawing_assets=Wei(0),
            redemption_assets=Wei(0),
            exit_queue_cumulative_ticket=exit_queue_cumulative_ticket,
        ),
        harvest_params=harvest_params,
        block_number=chain_head.block_number,
    )

    if settings.network in GNO_NETWORKS:
        # apply GNO -> mGNO exchange rate
        missing_assets = convert_to_mgno(missing_assets)
        total_assets = convert_to_mgno(total_assets)

    return ExitQueueAssets(
        missing=_wei_to_gwei_round_up(missing_assets),
        total=_wei_to_gwei_round_up(total_assets),
    )


def calculate_withdrawal_buffer(
    total_queue_assets: Gwei,
    pending_partials_count: int,
    avg_reward_per_second: int,
    rewards_delay: int,
    network_config: NetworkConfig,
) -> Gwei:
    """
    The exit queue is share-denominated and keeps accruing rewards on `total_queue_assets`
    while an EL-triggered partial withdrawal request for it waits through
    `MIN_VALIDATOR_WITHDRAWABILITY_DELAY_EPOCHS`, its turn in the network-wide pending-partials
    sweep, and the next vault harvest (`rewards_delay`). Requesting only the exact shortfall
    would leave a new dust shortfall at every reward update, so the request is padded with the
    rewards expected to accrue over that whole latency window, times a safety factor. Any excess
    lands as withdrawable assets in the vault and is re-staked by the normal funding path.
    """
    latency_seconds = (
        network_config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY_EPOCHS * network_config.SECONDS_PER_EPOCH
        + pending_partials_count
        * network_config.SECONDS_PER_SLOT
        // network_config.MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP
        + rewards_delay
    )
    buffer = (
        total_queue_assets
        * avg_reward_per_second
        * latency_seconds
        * WITHDRAWAL_BUFFER_SAFETY_FACTOR
        // 10**18
    )
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


def _wei_to_gwei_round_up(amount: Wei) -> Gwei:
    # Round up so wei-level dust below 1 gwei is never truncated away.
    return Gwei(-(-amount // 10**9))
