import logging

from eth_typing import ChecksumAddress, HexStr
from sw_utils import ChainHead, InterruptHandler, ProtocolConfig
from web3 import Web3
from web3.types import BlockNumber, Gwei

from src.common.app_state import AppState
from src.common.clients import execution_client
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import VaultContract
from src.common.execution import get_execution_request_fee, get_protocol_config
from src.common.harvest import get_harvest_params
from src.common.tasks import BaseTask
from src.common.utils import format_error, round_down
from src.config.settings import (
    MAX_WITHDRAWAL_REQUEST_FEE,
    MIN_ACTIVATION_BALANCE_GWEI,
    PARTIAL_WITHDRAWALS_INTERVAL,
    settings,
)
from src.validators.consensus import fetch_compounding_validators_balances
from src.withdrawals.assets import get_vault_assets

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

        harvest_params = await get_harvest_params(vault_address)
        total_assets, queued_assets = await get_vault_assets(
            vault_address=vault_address,
            harvest_params=harvest_params,
            protocol_config=protocol_config,
            chain_head=chain_head,
        )
        if (
            queued_assets
            < (protocol_config.validators_exit_queued_assets_bps * total_assets) / 10000
        ):
            return
        validators = await fetch_compounding_validators_balances(vault_address)
        available_partial_withdrawals_capacity = sum(
            balance - MIN_ACTIVATION_BALANCE_GWEI for balance in validators.values()
        )
        if available_partial_withdrawals_capacity < queued_assets:
            logger.info('Available partial withdrawals capacity is less than queued assets')
            return

        current_fee = await get_execution_request_fee(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            block_number=chain_head.block_number,
        )
        if current_fee > MAX_WITHDRAWAL_REQUEST_FEE:
            logger.info(
                'Partial withdrawals is skipped because high withdrawals fee, current fees is %s',
                current_fee,
            )
            return
        withdrawable_validators = _get_withdrawable_validators(validators, queued_assets)
        tx_hash = await submit_withdraw_validators(
            vault_address=vault_address,
            validators=_encode_validators(withdrawable_validators),
            current_fee=current_fee,
        )
        if not tx_hash:
            return

        app_state.partial_withdrawal_cache[vault_address] = chain_head.block_number
        logger.info(
            'Successfully withrawned %s %s for validators with public keys %s, tx hash: %s',
            round_down(Web3.from_wei(Web3.to_wei(queued_assets, 'gwei'), 'ether'), 2),
            settings.network_config.VAULT_BALANCE_SYMBOL,
            ', '.join([str(index) for index in withdrawable_validators]),
            tx_hash,
        )

    async def _check_withdrawals_block(
        self, app_state: AppState, vault_address: ChecksumAddress, block_number: BlockNumber
    ) -> bool:
        last_withdrawals_block = app_state.partial_withdrawal_cache.get(vault_address)
        partial_withdrawals_blocks_interval = (
            PARTIAL_WITHDRAWALS_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
        )
        if not last_withdrawals_block:
            vault_contract = VaultContract(vault_address)
            last_withdrawals_block = await vault_contract.get_last_partial_withdrawals_block()
        if (
            last_withdrawals_block
            and last_withdrawals_block + partial_withdrawals_blocks_interval >= block_number
        ):
            return False
        return True


def _get_withdrawable_validators(
    vault_validators: dict[HexStr, Gwei], withdrawals_amount: int
) -> dict[HexStr, int]:
    withdrawals_data = {}

    # can be executed in single request
    for public_key, balance in sorted(
        vault_validators.items(), key=lambda item: item[1], reverse=False
    ):
        if balance - MIN_ACTIVATION_BALANCE_GWEI >= withdrawals_amount:
            withdrawals_data[public_key] = withdrawals_amount
            return withdrawals_data

    # need to split withdrawal amount between validators
    for public_key, balance in sorted(
        vault_validators.items(), key=lambda item: item[1], reverse=True
    ):
        validators_amount = balance - MIN_ACTIVATION_BALANCE_GWEI
        if validators_amount > 0:
            withdrawals_data[public_key] = min(validators_amount, withdrawals_amount)
            withdrawals_amount -= min(validators_amount, withdrawals_amount)
        if withdrawals_amount <= 0:
            break

    return withdrawals_data


def _encode_validators(validators: dict[HexStr, int]) -> bytes:
    """
    Encodes validators data for withdrawValidators contract call
    """
    data = b''
    for public_key, amount in validators.items():
        data += Web3.to_bytes(hexstr=public_key)
        data += amount.to_bytes(8, byteorder='big')

    return data


async def submit_withdraw_validators(
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
