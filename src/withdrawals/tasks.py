import logging
from typing import cast

from eth_typing import HexStr
from sw_utils import (
    GNO_NETWORKS,
    ChainHead,
    ProtocolConfig,
    ValidatorStatus,
    convert_to_gno,
)
from web3 import Web3
from web3.types import BlockNumber, Gwei

from src.common.app_state import AppState
from src.common.clients import consensus_client, execution_client
from src.common.contracts import VaultContract
from src.common.execution import get_execution_request_fee, get_protocol_config
from src.common.metrics import metrics
from src.common.utils import round_down
from src.config.settings import (
    MAX_WITHDRAWAL_REQUEST_FEE,
    MIN_WITHDRAWAL_AMOUNT_GWEI,
    WITHDRAWALS_INTERVAL,
    ValidatorsRegistrationMode,
    settings,
)
from src.validators.consensus import fetch_consensus_validators
from src.validators.database import VaultValidatorCrud
from src.validators.exceptions import EmptyRelayerResponseException
from src.validators.oracles import poll_active_exits
from src.validators.relayer import RelayerClient
from src.validators.typings import ConsensusValidator
from src.withdrawals.assets import get_queued_assets
from src.withdrawals.execution import submit_withdraw_validators

logger = logging.getLogger(__name__)


class WithdrawalIntervalMixin:
    async def _is_withdrawal_interval_passed(
        self, app_state: AppState, chain_head: ChainHead
    ) -> bool:
        last_withdrawals_block = app_state.partial_withdrawal_block

        partial_withdrawals_blocks_interval = (
            WITHDRAWALS_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
        )
        from_block = BlockNumber(chain_head.block_number - partial_withdrawals_blocks_interval)
        if not last_withdrawals_block:
            last_withdrawals_block = await self._fetch_last_withdrawals_block(from_block)
            app_state.partial_withdrawal_block = last_withdrawals_block

        if (
            last_withdrawals_block
            and last_withdrawals_block + partial_withdrawals_blocks_interval
            >= chain_head.block_number
        ):
            return False
        return True

    async def _fetch_last_withdrawals_block(self, from_block: BlockNumber) -> BlockNumber | None:
        """
        Fetches withdrawal events within the specified interval.
        Returns the block number of the last withdrawal event, or None if not found.
        """
        vault_contract = VaultContract(settings.vault)
        events = await vault_contract.get_validator_withdrawal_submitted_events(from_block)
        if events:
            return events[-1].block_number

        return None


class ValidatorWithdrawalSubtask(WithdrawalIntervalMixin):

    def __init__(
        self,
        relayer: RelayerClient | None,
    ):
        self.relayer = relayer

    async def process(self, chain_head: ChainHead) -> None:
        """
        Every N hours check the exit queue and submit partial withdrawals if needed.
        """
        protocol_config = await get_protocol_config()
        app_state = AppState()
        if not await self._is_withdrawal_interval_passed(app_state, chain_head):
            return

        vault_validators = VaultValidatorCrud().get_vault_validators()
        consensus_validators = await fetch_consensus_validators(
            [val.public_key for val in vault_validators]
        )
        oracle_exiting_validators = await _fetch_oracle_exiting_validators(
            consensus_validators, protocol_config
        )

        queued_assets = await get_queued_assets(
            consensus_validators=consensus_validators,
            oracle_exiting_validators=oracle_exiting_validators,
            chain_head=chain_head,
        )
        metrics.queued_assets.labels(network=settings.network).set(int(queued_assets))

        if queued_assets < MIN_WITHDRAWAL_AMOUNT_GWEI:
            return

        current_fee = await get_execution_request_fee(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        )
        if current_fee > MAX_WITHDRAWAL_REQUEST_FEE:
            logger.info(
                'Partial withdrawals are skipped due to high withdrawal fee, '
                'the current fee is %s.',
                current_fee,
            )
            return
        if await _is_pending_partial_withdrawals_queue_full():
            logger.info(
                'Partial withdrawals are currently skipped because '
                'the pending partial withdrawals queue has exceeded its limit.'
            )
            return
        withdrawals = await _get_withdrawals(
            chain_head=chain_head,
            queued_assets=queued_assets,
            consensus_validators=consensus_validators,
            validator_min_active_epochs=protocol_config.validator_min_active_epochs,
            oracle_exit_indexes={val.index for val in oracle_exiting_validators},
        )
        if not withdrawals:
            logger.info(
                'No eligible validators found for withdrawal of %s Gwei',
                queued_assets,
            )
            return

        validators_manager_signature = HexStr('0x')
        if settings.validators_registration_mode == ValidatorsRegistrationMode.API:
            # fetch validator manager signature from relayer
            relayer_response = await cast(RelayerClient, self.relayer).withdraw_validators(
                withdrawals=withdrawals,
            )
            if not relayer_response.validators_manager_signature:
                logger.debug('Waiting for relayer validator manager signature')
                raise EmptyRelayerResponseException()

            validators_manager_signature = relayer_response.validators_manager_signature

        tx_hash = await submit_withdraw_validators(
            withdrawals=withdrawals,
            tx_fee=current_fee,
            validators_manager_signature=validators_manager_signature,
        )
        if not tx_hash:
            return

        app_state.partial_withdrawal_block = chain_head.block_number

        withdrawn_assets = Web3.to_wei(queued_assets, 'gwei')
        if settings.network in GNO_NETWORKS:
            # apply mGNO -> GNO exchange rate
            withdrawn_assets = convert_to_gno(withdrawn_assets)

        logger.info(
            'Successfully withdrawn %s %s for validators with public keys %s, tx hash: %s',
            round_down(Web3.from_wei(withdrawn_assets, 'ether'), 2),
            settings.network_config.VAULT_BALANCE_SYMBOL,
            ', '.join(withdrawals.keys()),
            tx_hash,
        )
        tx_data = await execution_client.eth.get_transaction(tx_hash)
        metrics.last_withdrawal_block.labels(network=settings.network).set(tx_data['blockNumber'])


async def _get_withdrawals(
    chain_head: ChainHead,
    queued_assets: Gwei,
    consensus_validators: list[ConsensusValidator],
    validator_min_active_epochs: int,
    oracle_exit_indexes: set[int],
) -> dict[HexStr, Gwei]:
    if queued_assets <= 0:
        return {}

    # Find all partial-withdrawable validators
    partial_validators = [
        v for v in consensus_validators if v.is_partially_withdrawable(chain_head.epoch)
    ]
    partial_capacity = sum(v.withdrawal_capacity for v in partial_validators)

    # If enough partials, use only them
    if partial_capacity >= queued_assets or settings.disable_full_withdrawals:
        return _get_partial_withdrawals(partial_validators, queued_assets)

    # Otherwise, add full withdrawals as needed
    max_activation_epoch = min(
        chain_head.epoch - validator_min_active_epochs,  # sw protocol limitation
        chain_head.epoch
        - settings.network_config.SHARD_COMMITTEE_PERIOD,  # consensus layer limitation
    )
    exitable_validators = _filter_exitable_validators(
        consensus_validators=consensus_validators,
        max_activation_epoch=max(max_activation_epoch, 0),
        oracle_exit_indexes=oracle_exit_indexes,
    )

    withdrawals: dict[HexStr, Gwei] = {}
    for validator in exitable_validators:
        if queued_assets <= 0:
            break

        withdrawals[validator.public_key] = Gwei(0)  # full withdrawal
        queued_assets = Gwei(max(0, queued_assets - validator.balance))

        # Remove exited validator from partials
        partial_capacity = Gwei(partial_capacity - validator.withdrawal_capacity)
        if partial_capacity >= queued_assets:
            partials = _get_partial_withdrawals(
                [p for p in partial_validators if p.public_key not in withdrawals],
                queued_assets,
            )
            withdrawals.update(partials)
            queued_assets = Gwei(max(0, queued_assets - sum(partials.values())))

    return withdrawals


def _get_partial_withdrawals(
    partial_validators: list[ConsensusValidator], queued_assets: Gwei
) -> dict[HexStr, Gwei]:
    withdrawals: dict[HexStr, Gwei] = {}

    if queued_assets <= 0:
        return withdrawals
    for validator in sorted(partial_validators, key=lambda item: item.balance, reverse=True):
        available = validator.withdrawal_capacity
        if available <= 0:
            continue

        amount = Gwei(min(available, queued_assets))
        withdrawals[validator.public_key] = amount
        queued_assets = Gwei(queued_assets - amount)

        if queued_assets <= 0:
            break

    return withdrawals


def _filter_exitable_validators(
    consensus_validators: list[ConsensusValidator],
    max_activation_epoch: int,
    oracle_exit_indexes: set[int],
) -> list[ConsensusValidator]:
    """
    Return validators eligible for exit,
    ordered by balance to minimize assets exited.
    """
    can_be_exited_validators = []
    for validator in consensus_validators:
        if validator.activation_epoch > max_activation_epoch:
            continue
        if validator.status != ValidatorStatus.ACTIVE_ONGOING:
            continue
        if validator.index in oracle_exit_indexes:
            continue
        can_be_exited_validators.append(validator)
    can_be_exited_validators.sort(key=lambda x: (x.balance, x.index))

    return can_be_exited_validators


async def _fetch_oracle_exiting_validators(
    consensus_validators: list[ConsensusValidator], protocol_config: ProtocolConfig
) -> list[ConsensusValidator]:
    """Fetch exiting validator indexes from oracles and filter them from consensus validators."""
    vault_indexes = {val.index for val in consensus_validators}
    oracles_exits_indexes = await poll_active_exits(protocol_config=protocol_config)
    vault_oracles_exiting_indexes = [
        index for index in oracles_exits_indexes if index in vault_indexes
    ]
    return [val for val in consensus_validators if val.index in vault_oracles_exiting_indexes]


async def _is_pending_partial_withdrawals_queue_full() -> bool:
    pending_partial_withdrawals = await consensus_client.get_pending_partial_withdrawals()
    queue_length = len(pending_partial_withdrawals)
    return queue_length >= settings.network_config.PENDING_PARTIAL_WITHDRAWALS_LIMIT
