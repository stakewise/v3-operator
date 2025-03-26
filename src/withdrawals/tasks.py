import logging

from eth_typing import HexStr
from sw_utils import InterruptHandler
from web3 import Web3

from src.common.checks import wait_execution_catch_up_consensus
from src.common.clients import execution_client
from src.common.consensus import fetch_registered_validators, get_chain_finalized_head
from src.common.contracts import vault_contract
from src.common.execution import get_protocol_config
from src.common.harvest import get_harvest_params
from src.common.tasks import BaseTask
from src.common.typings import Validator, ValidatorType
from src.common.utils import format_error
from src.config.settings import (
    DEPOSIT_AMOUNT,
    DEPOSIT_AMOUNT_GWEI,
    PARTIAL_WITHDRAWALS_INTERVAL,
    settings,
)
from src.withdrawals.execution import get_vault_assets

logger = logging.getLogger(__name__)


class PartialWithdrawalsTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """
        Every N hours check the exit queue and submit partial withdrawals for deposits.
        Add limit on fee.
        """
        chain_head = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(
            chain_state=chain_head, interrupt_handler=interrupt_handler
        )
        protocol_config = await get_protocol_config()
        last_withdrawals_block = await _get_last_withdrawals_block()  # via contract event?
        if (
            last_withdrawals_block
            and last_withdrawals_block + PARTIAL_WITHDRAWALS_INTERVAL >= chain_head.block_number
        ):
            return

        harvest_params = await get_harvest_params()
        queued_assets, total_assets = await get_vault_assets(
            vault=settings.vault,
            block_number=chain_head.block_number,
            harvest_params=harvest_params,
        )
        if (
            queued_assets
            < (protocol_config.validators_exit_queued_assets_bps * total_assets) / 10000
        ):
            return

        validators = await fetch_registered_validators()
        validators = [v for v in validators if v.validator_type == ValidatorType.TWO]
        partial_withdrawals_amount = sum(v.balance - DEPOSIT_AMOUNT for v in validators)

        if partial_withdrawals_amount < queued_assets:
            logger.info('Partial withdrawals amount is less than queued assets')
            return

        withdrawals_data = _get_withdrawal_data(validators, partial_withdrawals_amount)
        tx_hash = await submit_partial_withdrawals_request(
            validators=withdrawals_data, validators_manager_signature=validators_manager_signature
        )
        if not tx_hash:
            return

        logger.info(
            'Successfully withrawned %s eth for validators with public keys %s, tx hash: %s',
            queued_assets,
            ', '.join([str(index) for index in withdrawals_data]),
            tx_hash,
        )


def _get_withdrawal_data(validators: list[Validator], withdrawals_amount: int) -> dict[HexStr, int]:
    """
    Returns withdrawal data for partial withdrawals
    withdrawals_amount - total amount of queued assets,
    more than available for partial withdrawals assets
    """
    validators.sort(key=lambda x: x.balance, reverse=False)
    withdrawals_data = {}

    # can be executed in single request
    for v in validators:
        if v.balance - DEPOSIT_AMOUNT_GWEI >= withdrawals_amount:
            withdrawals_data[v.public_key] = withdrawals_amount
            return withdrawals_data

    # need to split withdrawal amount between validators
    for v in validators[::-1]:
        validators_amount = v.balance - DEPOSIT_AMOUNT_GWEI
        if validators_amount > 0:
            withdrawals_data[v.public_key] = min(validators_amount, withdrawals_amount)
            withdrawals_amount -= min(validators_amount, withdrawals_amount)
        if withdrawals_amount <= 0:
            break
    # assert withdrawals_amount == 0

    return withdrawals_data


async def submit_partial_withdrawals_request(
    validators: bytes,
    validators_manager_signature: bytes,
) -> HexStr | None:
    """Sends consolidateValidators transaction to vault contract"""
    logger.info('Submitting consolidateValidators transaction')
    try:
        tx = await vault_contract.functions.consolidateValidators(
            validators,
            validators_manager_signature,
        ).transact()
    except Exception as e:
        logger.info('Failed to update exit signatures: %s', format_error(e))
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.info('UpdateExitSignatures transaction failed')
        return None
    return Web3.to_hex(tx)
