import logging

from eth_typing import ChecksumAddress, HexStr
from sw_utils import ChainHead, InterruptHandler, ProtocolConfig
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
from src.withdrawals.assets import CAN_BE_EXITED_STATUSES, get_queued_assets

logger = logging.getLogger(__name__)


class PartialWithdrawalsTask(BaseTask):
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
        if not await self._check_withdrawals_block(
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

        queued_assets = await get_queued_assets(  # todo: queued or missing - unify
            vault_address=vault_address,
            consensus_validators=consensus_validators,
            oracle_exiting_validators=oracle_exiting_validators,
            chain_head=chain_head,
        )
        if queued_assets < MIN_WITHDRAWAL_AMOUNT_GWEI:
            return

        # filter active validators
        active_validators = [
            val
            for val in consensus_validators
            if _is_withdrawable_validators(val, chain_head.epoch)
        ]

        available_partial_withdrawals_capacity = sum(
            val.balance - MIN_ACTIVATION_BALANCE_GWEI for val in active_validators
        )

        current_fee = await get_execution_request_fee(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            block_number=chain_head.block_number,
        )
        if current_fee > MAX_WITHDRAWAL_REQUEST_FEE:
            logger.info(
                'Partial withdrawals are skipped due to high withdrawal fees, '
                'the current fee is %s.',
                current_fee,
            )
            return
        withdrawals_data = _get_partial_withdrawals_data(  # todo: full withdrawals first?
            validator_balances={val.public_key: val.balance for val in active_validators},
            queued_assets=queued_assets,
        )

        if available_partial_withdrawals_capacity < queued_assets:
            logger.info('Available partial withdrawals capacity is less than queued assets')
            if not settings.disable_full_withdrawals:
                logger.info('Full withdrawals')
                full_withdrawals = await _get_full_withdrawals_data(
                    chain_head=chain_head,
                    missing_assets=Gwei(queued_assets - sum(withdrawals_data.values())),
                    consensus_validators=consensus_validators,
                    protocol_config=protocol_config,
                    oracle_exit_indexes={val.index for val in oracle_exiting_validators},
                )
                withdrawals_data = full_withdrawals | withdrawals_data

        app_state.partial_withdrawal_cache[vault_address] = chain_head.block_number

        tx_hash = await _submit_withdraw_validators(
            vault_address=vault_address,
            validators=_encode_withdrawals_data(withdrawals_data),
            current_fee=current_fee,
        )
        if not tx_hash:
            return

        logger.info(
            'Successfully withrawned %s %s for validators with public keys %s, tx hash: %s',
            round_down(Web3.from_wei(Web3.to_wei(queued_assets, 'gwei'), 'ether'), 2),
            settings.network_config.VAULT_BALANCE_SYMBOL,
            ', '.join([str(index) for index in withdrawals_data]),
            tx_hash,
        )

    async def _check_withdrawals_block(
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
        withdrawals_events = await vault_contract.get_validator_withdrawal_submitted_events(
            from_block
        )
        consensus_validators = await fetch_consensus_validators(
            [event.public_key for event in withdrawals_events]
        )
        public_key_to_index = {val.public_key: val.index for val in consensus_validators}

        for event in withdrawals_events:
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


async def _get_full_withdrawals_data(
    chain_head: ChainHead,
    missing_assets: Gwei,
    consensus_validators: list[ConsensusValidator],
    protocol_config: ProtocolConfig,
    oracle_exit_indexes: set[int],
) -> dict[HexStr, int]:
    """"""
    max_activation_epoch = max(0, chain_head.epoch - protocol_config.validator_min_active_epochs)
    withdrawals_data: dict[HexStr, int] = {}

    if not consensus_validators or not missing_assets:
        return withdrawals_data
    can_be_exited_validators = _filter_exitable_validators(
        consensus_validators=consensus_validators,
        max_activation_epoch=max_activation_epoch,
        oracle_exit_indexes=oracle_exit_indexes,
    )

    for validator in can_be_exited_validators:
        if sum(withdrawals_data.values()) >= missing_assets:
            break
        withdrawals_data[validator.public_key] = validator.balance

    return withdrawals_data


def _get_partial_withdrawals_data(
    validator_balances: dict[HexStr, Gwei], queued_assets: int
) -> dict[HexStr, int]:
    """"""
    withdrawals_data = {}

    # can be executed in single request
    for public_key, balance in sorted(
        validator_balances.items(), key=lambda item: item[1], reverse=False
    ):
        if balance - MIN_ACTIVATION_BALANCE_GWEI >= queued_assets:
            withdrawals_data[public_key] = queued_assets
            return withdrawals_data

    # need to split withdrawal amount between validators
    for public_key, balance in sorted(
        validator_balances.items(), key=lambda item: item[1], reverse=True
    ):
        validators_amount = balance - MIN_ACTIVATION_BALANCE_GWEI
        if validators_amount > 0:
            withdrawals_data[public_key] = min(validators_amount, queued_assets)
            queued_assets -= min(validators_amount, queued_assets)
        if queued_assets <= 0:
            break

    return withdrawals_data


def _encode_withdrawals_data(withdrawable_data: dict[HexStr, int]) -> bytes:
    """
    Encodes validators data for withdrawValidators contract call
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
        logger.info('Failed to withdrawal validators: %s', format_error(e))
        return None

    vault_contract = VaultContract(vault_address)

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


def _is_withdrawable_validators(validator: ConsensusValidator, epoch: int) -> bool:
    # todo: rename
    if validator.status not in CAN_BE_EXITED_STATUSES:
        return False
    # filter validator that was active long enough
    if epoch < validator.activation_epoch + settings.network_config.SHARD_COMMITTEE_PERIOD:
        return False
    return True


def _filter_exitable_validators(
    consensus_validators: list[ConsensusValidator],
    max_activation_epoch: int,
    oracle_exit_indexes: set[int],
) -> list[ConsensusValidator]:
    # Retrieve validators that are either in the process of exiting or eligible for exit.
    # Order by balance to exit as minimal assets as possible.
    can_be_exited_validators = []
    for validator in consensus_validators:
        if validator.activation_epoch > max_activation_epoch:  # todo
            continue
        if validator.status not in CAN_BE_EXITED_STATUSES:
            continue
        if validator.index in oracle_exit_indexes:
            continue
        can_be_exited_validators.append(validator)
    can_be_exited_validators.sort(key=lambda x: (x.balance, x.index))

    return can_be_exited_validators


async def _fetch_oracle_exiting_validators(
    consensus_validators: list[ConsensusValidator], protocol_config: ProtocolConfig
) -> list[ConsensusValidator]:
    """"""
    vault_indexes = {val.index for val in consensus_validators}
    oracles_exits_indexes = await poll_active_exits(protocol_config=protocol_config)
    vault_oracles_exiting_indexes = [
        index for index in oracles_exits_indexes if index in vault_indexes
    ]
    vault_oracles_exiting_validators = []
    for val in consensus_validators:
        if val.index in vault_oracles_exiting_indexes:
            vault_oracles_exiting_validators.append(val)
        else:
            raise ValueError('Invalid validator index in vault oracles exiting indexes')

    return vault_oracles_exiting_validators
