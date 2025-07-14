from sw_utils import ChainHead, ProtocolConfig, ValidatorStatus, convert_to_mgno
from sw_utils.networks import GNO_NETWORKS
from web3 import Web3
from web3.types import ChecksumAddress, Gwei, Wei

from src.common.clients import consensus_client
from src.common.contracts import (
    VaultContract,
    multicall_contract,
    validators_checker_contract,
)
from src.common.typings import ExitQueueMissingAssetsParams, HarvestParams
from src.config.settings import settings
from src.harvest.execution import get_update_state_calls
from src.validators.consensus import fetch_consensus_validators
from src.validators.database import VaultValidatorCrud
from src.validators.oracles import poll_active_exits
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


async def get_vault_assets(
    vault_address: ChecksumAddress,
    harvest_params: HarvestParams | None,
    chain_head: ChainHead,
    protocol_config: ProtocolConfig,
) -> tuple[Gwei, Gwei]:
    """Get the total assets and queued assets in the vault."""
    total_assets = await _get_total_assets(
        vault_address=vault_address,
        harvest_params=harvest_params,
    )
    queued_assets = await _get_queued_assets(
        vault_address=vault_address,
        harvest_params=harvest_params,
        chain_head=chain_head,
        protocol_config=protocol_config,
    )
    return Gwei(int(Web3.from_wei(total_assets, 'gwei'))), Gwei(
        int(Web3.from_wei(queued_assets, 'gwei'))
    )


async def _get_queued_assets(
    vault_address: ChecksumAddress,
    harvest_params: HarvestParams | None,
    protocol_config: ProtocolConfig,
    chain_head: ChainHead,
) -> Wei:
    # Get exit queue cumulative tickets
    exit_queue_cumulative_ticket = (
        await validators_checker_contract.get_exit_queue_cumulative_tickets(
            vault_address=vault_address,
            harvest_params=harvest_params,
            block_number=chain_head.block_number,
        )
    )
    vault_validators = VaultValidatorCrud().get_vault_validators(
        vault_address=vault_address,
    )

    consensus_validators = await fetch_consensus_validators(
        [v.public_key for v in vault_validators]
    )

    pending_partial_withdrawals_sum = await _get_pending_partial_withdrawals_sum(
        validator_indexes=[
            str(v.index) for v in consensus_validators if v.status in CAN_BE_EXITED_STATUSES
        ],
        slot=chain_head.slot,
    )
    validators_exits_sum = await _get_validators_sum(
        consensus_validators=consensus_validators,
        protocol_config=protocol_config,
    )

    # Withdrawing assets are assets that are ready to cover the exit requests
    # but not yet used to fulfill exit requests.
    withdrawing_assets = Wei(pending_partial_withdrawals_sum + validators_exits_sum)

    # Missing assets express how much assets are needed to cover the exit requests
    # until the exit queue cumulative ticket is reached
    missing_assets = await validators_checker_contract.get_exit_queue_missing_assets(
        exit_queue_missing_assets_params=ExitQueueMissingAssetsParams(
            vault=vault_address,
            withdrawing_assets=withdrawing_assets,
            exit_queue_cumulative_ticket=exit_queue_cumulative_ticket,
        ),
        harvest_params=harvest_params,
        block_number=chain_head.block_number,
    )
    return missing_assets


async def _get_pending_partial_withdrawals_sum(
    validator_indexes: list[str],
    slot: int,
) -> Wei:
    """
    Calculate the sum of pending partial withdrawals for current moment
    """
    pending_partial_withdrawals_sum = 0
    pending_withdrawals_data = await consensus_client.get_pending_partial_withdrawals(str(slot))
    for pending_withdrawal_item in pending_withdrawals_data:
        index = pending_withdrawal_item['validator_index']

        if index not in validator_indexes:
            continue

        amount = Web3.to_wei(pending_withdrawal_item['amount'], 'gwei')
        pending_partial_withdrawals_sum += amount
    return Web3.to_wei(pending_partial_withdrawals_sum, 'gwei')


async def _get_validators_sum(
    consensus_validators: list[ConsensusValidator], protocol_config: ProtocolConfig
) -> Wei:
    """
    Calculate the sum of active validators exits. Consists of two parts:
    1. fetch active exits from oracles.
    2. fetch manually exited validators.
    """
    # 1. Validator exits
    # validator status can be not changed yet, so fetch active exits from oracles
    vault_indexes = {val.index for val in consensus_validators}
    oracles_exits_indexes = await poll_active_exits(protocol_config=protocol_config)
    vault_oracles_exiting_indexes = [
        index for index in oracles_exits_indexes if index in vault_indexes
    ]
    vault_oracles_exiting_validators = [
        val for val in consensus_validators if val.index in vault_oracles_exiting_indexes
    ]
    oracle_exiting_balance = sum(val.balance for val in vault_oracles_exiting_validators)
    # 2. Validator manually exits
    manually_exiting_balance = sum(
        val.balance
        for val in consensus_validators
        if val.status in EXITING_STATUSES and val.index not in vault_oracles_exiting_indexes
    )

    return Web3.to_wei(oracle_exiting_balance + manually_exiting_balance, 'gwei')


async def _get_total_assets(
    vault_address: ChecksumAddress,
    harvest_params: HarvestParams | None = None,
) -> Wei:
    vault_contract = VaultContract(vault_address)
    if harvest_params is not None:
        calls = await get_update_state_calls(
            vault_address=vault_address, harvest_params=harvest_params
        )
    else:
        calls = []
    calls.extend(
        [
            (vault_address, vault_contract.encode_abi('totalAssets')),
        ]
    )
    _, multicall = await multicall_contract.aggregate(calls)
    total_assets = Wei(Web3.to_int(multicall[-1]))

    if settings.network in GNO_NETWORKS:
        total_assets = convert_to_mgno(Wei(total_assets))

    return total_assets
