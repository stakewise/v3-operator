import logging

from eth_typing import ChecksumAddress, HexStr
from sw_utils import ChainHead, InterruptHandler, ProtocolConfig, ValidatorStatus
from web3 import Web3
from web3.types import BlockNumber, Gwei

from src.common.app_state import AppState
from src.common.clients import consensus_client, execution_client
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import VaultContract
from src.common.execution import get_execution_request_fee, get_protocol_config
from src.common.tasks import BaseTask
from src.common.utils import calc_slot_by_block_number, format_error, round_down
from src.config.settings import (
    MAX_WITHDRAWAL_REQUEST_FEE,
    MIN_ACTIVATION_BALANCE_GWEI,
    MIN_WITHDRAWAL_AMOUNT_GWEI,
    PARTIAL_WITHDRAWALS_INTERVAL,
    settings,
)
from src.validators.consensus import fetch_consensus_validators
from src.validators.database import VaultValidatorCrud
from src.validators.oracles import poll_active_exits
from src.validators.typings import ConsensusValidator
from src.withdrawals.assets import get_queued_assets

logger = logging.getLogger(__name__)


class WithdrawalsTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """
        Every N hours check the exit queue and submit partial withdrawals if needed.
        """
        chain_head = await get_chain_finalized_head()
        protocol_config = await get_protocol_config()
        for vault_address in settings.vaults:
            await self.process_withdrawals(
                vault_address=vault_address,
                chain_head=chain_head,
                protocol_config=protocol_config,
            )

    async def process_withdrawals(
        self,
        vault_address: ChecksumAddress,
        chain_head: ChainHead,
        protocol_config: ProtocolConfig,
    ) -> None:
        app_state = AppState()
        if not await self._is_withdrawal_interval_passed(
            app_state, vault_address, chain_head.block_number
        ):
            return

        vault_validators = VaultValidatorCrud().get_vault_validators(
            vault_address=vault_address,
        )
        consensus_validators = await fetch_consensus_validators(
            [val.public_key for val in vault_validators]
        )
        oracle_exiting_validators = await _fetch_oracle_exiting_validators(
            consensus_validators, protocol_config
        )

        queued_assets = await get_queued_assets(
            vault_address=vault_address,
            consensus_validators=consensus_validators,
            oracle_exiting_validators=oracle_exiting_validators,
            chain_head=chain_head,
        )
        if queued_assets < MIN_WITHDRAWAL_AMOUNT_GWEI:
            app_state.partial_withdrawal_cache[vault_address] = chain_head.block_number
            return

        current_fee = await get_execution_request_fee(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            block_number=chain_head.block_number,
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
        withdrawals_data = await _get_withdrawals_data(
            chain_head=chain_head,
            queued_assets=queued_assets,
            consensus_validators=consensus_validators,
            validator_min_active_epochs=protocol_config.validator_min_active_epochs,
            oracle_exit_indexes={val.index for val in oracle_exiting_validators},
        )

        tx_hash = await _submit_withdraw_validators(
            vault_address=vault_address,
            validators=_encode_withdrawals_data(withdrawals_data),
            current_fee=current_fee,
        )
        if not tx_hash:
            return

        app_state.partial_withdrawal_cache[vault_address] = chain_head.block_number

        logger.info(
            'Successfully withdrawn %s %s for validators with public keys %s, tx hash: %s',
            round_down(Web3.from_wei(Web3.to_wei(queued_assets, 'gwei'), 'ether'), 2),
            settings.network_config.VAULT_BALANCE_SYMBOL,
            ', '.join([str(index) for index in withdrawals_data]),
            tx_hash,
        )

    async def _is_withdrawal_interval_passed(
        self, app_state: AppState, vault_address: ChecksumAddress, block_number: BlockNumber
    ) -> bool:
        last_withdrawals_block = app_state.partial_withdrawal_cache.get(vault_address)

        partial_withdrawals_blocks_interval = (
            PARTIAL_WITHDRAWALS_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
        )
        from_block = BlockNumber(block_number - partial_withdrawals_blocks_interval)
        if not last_withdrawals_block:
            last_withdrawals_block = await self._fetch_last_withdrawals_block(
                vault_address, from_block
            )
            app_state.partial_withdrawal_cache[vault_address] = last_withdrawals_block

        if (
            last_withdrawals_block
            and last_withdrawals_block + partial_withdrawals_blocks_interval >= block_number
        ):
            return False
        return True

    async def _fetch_last_withdrawals_block(
        self, vault_address: ChecksumAddress, from_block: BlockNumber
    ) -> BlockNumber | None:
        """
        Fetch withdrawal events for the required interval.
        Validate that the withdrawal was successful via a consensus request.
        Return the last event block number.
        """
        vault_contract = VaultContract(vault_address)
        events = await vault_contract.get_validator_withdrawal_submitted_events(from_block)
        consensus_validators = await fetch_consensus_validators(
            [event.public_key for event in events]
        )
        public_key_to_index = {val.public_key: val.index for val in consensus_validators}

        for event in events[::-1]:  # reverse order to get the latest event
            slot = await calc_slot_by_block_number(event.block_number)
            pending_partial_withdrawals = await consensus_client.get_pending_partial_withdrawals(
                slot
            )
            for withdrawal in pending_partial_withdrawals:
                if (
                    int(withdrawal['validator_index']) == public_key_to_index[event.public_key]
                    and Web3.to_wei(withdrawal['amount'], 'gwei') == event.amount
                ):
                    return event.block_number

        return None


async def _get_withdrawals_data(
    chain_head: ChainHead,
    queued_assets: Gwei,
    consensus_validators: list[ConsensusValidator],
    validator_min_active_epochs: int,
    oracle_exit_indexes: set[int],
) -> dict[HexStr, Gwei]:
    # Find all partial-withdrawable validators
    partials = [
        v for v in consensus_validators if _is_partial_withdrawable_validator(v, chain_head.epoch)
    ]
    partial_capacity = sum(v.balance - MIN_ACTIVATION_BALANCE_GWEI for v in partials)

    # If enough partials, use only them
    if partial_capacity >= queued_assets or settings.disable_full_withdrawals:
        return _get_partial_withdrawals_data(
            {v.public_key: v.balance for v in partials}, queued_assets
        )

    # Otherwise, add full withdrawals as needed
    min_epoch = max(0, chain_head.epoch - validator_min_active_epochs)
    exitable_validators = _filter_exitable_validators(
        consensus_validators, min_epoch, oracle_exit_indexes
    )
    withdrawals: dict[HexStr, Gwei] = {}
    exited_assets = 0

    for validator in exitable_validators:
        withdrawals[validator.public_key] = Gwei(0)  # full withdrawal
        exited_assets += validator.balance
        queued_assets = Gwei(queued_assets - validator.balance)
        # Remove exited validator from partials
        partials = [p for p in partials if p.public_key != validator.public_key]
        partial_capacity = sum(p.balance - MIN_ACTIVATION_BALANCE_GWEI for p in partials)
        if partial_capacity >= queued_assets:
            partials_data = _get_partial_withdrawals_data(
                {p.public_key: p.balance for p in partials}, queued_assets
            )
            withdrawals.update(partials_data)
            break

    return withdrawals


def _get_partial_withdrawals_data(
    validator_balances: dict[HexStr, Gwei], queued_assets: Gwei
) -> dict[HexStr, Gwei]:
    withdrawals_data: dict[HexStr, Gwei] = {}

    if queued_assets <= 0:
        return withdrawals_data
    for public_key, balance in sorted(
        validator_balances.items(), key=lambda item: item[1], reverse=True
    ):
        available = balance - MIN_ACTIVATION_BALANCE_GWEI
        if available <= 0:
            continue

        amount = Gwei(min(available, queued_assets))
        withdrawals_data[public_key] = amount
        queued_assets = Gwei(queued_assets - amount)

        if queued_assets <= 0:
            break

    return withdrawals_data


def _encode_withdrawals_data(withdrawable_data: dict[HexStr, Gwei]) -> bytes:
    """
    Encodes validator data for withdrawValidators contract call
    """
    data = b''
    for public_key, amount in withdrawable_data.items():
        data += Web3.to_bytes(hexstr=public_key)
        data += amount.to_bytes(8, byteorder='big')

    return data


async def _submit_withdraw_validators(
    vault_address: ChecksumAddress,
    validators: bytes,
    current_fee: Gwei,
) -> HexStr | None:
    """Sends withdrawValidators transaction to vault contract"""
    logger.info('Submitting withdrawValidators transaction')
    vault_contract = VaultContract(vault_address)
    try:
        tx = await vault_contract.functions.withdrawValidators(
            validators,
            b'',
        ).transact({'value': Web3.to_wei(current_fee, 'gwei')})
    except Exception as e:
        logger.info('Failed to withdraw from validators: %s', format_error(e))
        return None

    vault_contract.encode_abi(
        fn_name='withdrawValidators',
        args=[validators, b''],
    )

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.info('Withdraw validators transaction failed')
        return None
    return Web3.to_hex(tx)


def _is_partial_withdrawable_validator(validator: ConsensusValidator, epoch: int) -> bool:
    if not validator.is_compounding:
        return False
    if validator.status != ValidatorStatus.ACTIVE_ONGOING:
        return False
    # filter validator that was active long enough
    if epoch < validator.activation_epoch + settings.network_config.SHARD_COMMITTEE_PERIOD:
        return False
    return True


def _filter_exitable_validators(
    consensus_validators: list[ConsensusValidator],
    min_activation_epoch: int,
    oracle_exit_indexes: set[int],
) -> list[ConsensusValidator]:
    """
    Returns validators that are eligible for exit.
    Order by balance to exit as minimal assets as possible.
    """
    can_be_exited_validators = []
    for validator in consensus_validators:
        if validator.activation_epoch > min_activation_epoch:
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
    """Fetch exiting validators indexes from oracles and filter them from consensus validators."""
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
