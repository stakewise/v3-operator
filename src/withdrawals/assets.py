from sw_utils import ChainHead, ValidatorStatus
from web3 import Web3
from web3.types import ChecksumAddress, Gwei, Wei

from src.common.clients import consensus_client
from src.common.contracts import validators_checker_contract
from src.common.harvest import get_harvest_params
from src.common.typings import ExitQueueMissingAssetsParams
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
    vault_address: ChecksumAddress,
    consensus_validators: list[ConsensusValidator],
    oracle_exiting_validators: list[ConsensusValidator],
    chain_head: ChainHead,
) -> Gwei:
    harvest_params = await get_harvest_params(vault_address)

    # Get exit queue cumulative tickets
    exit_queue_cumulative_ticket = (
        await validators_checker_contract.get_exit_queue_cumulative_tickets(
            vault_address=vault_address,
            harvest_params=harvest_params,
            block_number=chain_head.block_number,
        )
    )
    # fetch current pending partial withdrawals from consensus client
    pending_partial_withdrawals_amount = await _get_pending_partial_withdrawals_amount(
        validator_indexes=[
            str(v.index) for v in consensus_validators if v.status in CAN_BE_EXITED_STATUSES
        ],
        slot=chain_head.slot,
    )
    # fetch active validators exits
    consolidations = await consensus_client.get_pending_consolidations()
    source_consolidations_indexes = {
        int(consolidation['source_index']) for consolidation in consolidations
    }
    validators_exits_amount = _calculate_validators_exits_amount(
        consensus_validators=consensus_validators,
        oracle_exiting_validators=oracle_exiting_validators,
        source_consolidations_indexes=source_consolidations_indexes,
    )

    # Withdrawing assets are assets that are ready to cover the exit requests
    # but not yet used to fulfill exit requests.
    withdrawing_assets = Wei(pending_partial_withdrawals_amount + validators_exits_amount)

    # Missing assets express how much assets are needed to cover the exit requests
    # until the exit queue cumulative ticket is reached
    queued_assets = await validators_checker_contract.get_exit_queue_missing_assets(
        exit_queue_missing_assets_params=ExitQueueMissingAssetsParams(
            vault=vault_address,
            withdrawing_assets=withdrawing_assets,
            exit_queue_cumulative_ticket=exit_queue_cumulative_ticket,
        ),
        harvest_params=harvest_params,
        block_number=chain_head.block_number,
    )
    return Gwei(int(Web3.from_wei(queued_assets, 'gwei')))


async def _get_pending_partial_withdrawals_amount(
    validator_indexes: list[str],
    slot: int,
) -> Wei:
    """
    Calculate the sum of pending partial withdrawals at the specified slot
    """
    if not validator_indexes:
        return Wei(0)

    total_pending_withdrawals = 0
    pending_withdrawals = await consensus_client.get_pending_partial_withdrawals(str(slot))
    for pending_withdrawal in pending_withdrawals:
        index = pending_withdrawal['validator_index']
        if index not in validator_indexes:
            continue

        total_pending_withdrawals += int(pending_withdrawal['amount'])

    return Web3.to_wei(total_pending_withdrawals, 'gwei')


def _calculate_validators_exits_amount(
    consensus_validators: list[ConsensusValidator],
    oracle_exiting_validators: list[ConsensusValidator],
    source_consolidations_indexes: set[int],
) -> Wei:
    """
    Calculate the sum of exiting validators balances. Calculated from two components:
    1. Active exits from oracles.
    2. Manually exited validators.
    """
    # 1. Validator exits
    # validator status can be not changed yet, so use active exits from oracles
    oracle_exiting_balance = sum(val.balance for val in oracle_exiting_validators)

    # 2. Validator manually exits
    manually_exiting_balance = sum(
        val.balance
        for val in consensus_validators
        if val.status in EXITING_STATUSES
        and val.index not in oracle_exiting_validators
        and val.index not in source_consolidations_indexes
    )

    return Web3.to_wei(oracle_exiting_balance + manually_exiting_balance, 'gwei')
