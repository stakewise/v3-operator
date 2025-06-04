import logging

from eth_typing import ChecksumAddress, HexStr
from sw_utils import ChainHead, InterruptHandler, ProtocolConfig
from web3 import Web3
from web3.types import Gwei

from src.common.app_state import AppState
from src.common.checks import wait_execution_catch_up_consensus
from src.common.clients import execution_client
from src.common.consensus import (
    fetch_v2_registered_validators,
    get_chain_finalized_head,
)
from src.common.contracts import VaultContract
from src.common.execution import get_protocol_config, get_request_fee
from src.common.harvest import get_harvest_params
from src.common.tasks import BaseTask
from src.common.typings import ConsensusValidator, HarvestParams, ValidatorType
from src.common.utils import format_error, round_down
from src.config.settings import (
    DEPOSIT_AMOUNT_GWEI,
    MAX_WITHDRAWAL_REQUEST_FEE,
    PARTIAL_WITHDRAWALS_INTERVAL,
    settings,
)
from src.withdrawals.execution import get_vault_assets
from src.withdrawals.validators_manager import (
    get_validators_manager_signature_withdrawals,
)

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
        for vault_address in settings.vaults:
            await self.process_withdrawals(
                vault_address=vault_address,
                chain_head=chain_head,
                protocol_config=protocol_config,
            )

    # pylint: disable-next=too-many-locals
    async def process_withdrawals(
        self, vault_address: ChecksumAddress, chain_head: ChainHead, protocol_config: ProtocolConfig
    ) -> None:
        app_state = AppState()
        last_withdrawals_block = app_state.partial_withdrawal_cache.get(vault_address)
        if not last_withdrawals_block:
            vault_contract = VaultContract(vault_address)
            last_withdrawals_block = await vault_contract.get_last_partial_withdrawals_block()
        if (
            last_withdrawals_block
            and last_withdrawals_block + PARTIAL_WITHDRAWALS_INTERVAL >= chain_head.block_number
        ):
            return

        harvest_params = await get_harvest_params(vault_address)
        queued_assets, total_assets = await get_vault_assets(
            vault_address=vault_address,
            harvest_params=harvest_params,
        )
        if (
            queued_assets
            < (protocol_config.validators_exit_queued_assets_bps * total_assets) / 10000
        ):
            return
        queued_assets_gwei = int(Web3.from_wei(queued_assets, 'gwei'))
        validators = await fetch_v2_registered_validators(vault_address)
        validators = [v for v in validators if v.validator_type == ValidatorType.TWO]
        available_partial_withdrawals_amount = sum(
            v.balance - DEPOSIT_AMOUNT_GWEI for v in validators
        )
        if available_partial_withdrawals_amount < queued_assets_gwei:
            logger.info('Partial withdrawals amount is less than queued assets')
            return

        current_fee = await get_request_fee(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            block_number=chain_head.block_number,
        )
        if current_fee > MAX_WITHDRAWAL_REQUEST_FEE:
            logger.info(
                'Partial withdrawals is skipped because high withdrawals fee, current fees is %s',
                current_fee,
            )
            return
        withdrawals_data = _get_withdrawal_data(validators, queued_assets_gwei)
        validator_data = _encode_validators(withdrawals_data)
        vault_contract = VaultContract(vault_address)
        nonce = await vault_contract.validators_manager_nonce()
        validators_manager_signature = get_validators_manager_signature_withdrawals(
            vault=vault_address,
            validator_data=validator_data,
            nonce=nonce,
        )
        tx_hash = await submit_withdraw_validators(
            vault_address=vault_address,
            validators=validator_data,
            validators_manager_signature=Web3.to_bytes(hexstr=validators_manager_signature),
            harvest_params=harvest_params,
            current_fee=current_fee,
        )
        if not tx_hash:
            return

        app_state.partial_withdrawal_cache[vault_address] = chain_head.block_number
        logger.info(
            'Successfully withrawned %s %s for validators with public keys %s, tx hash: %s',
            round_down(Web3.from_wei(queued_assets, 'ether'), 2),
            settings.network_config.VAULT_BALANCE_SYMBOL,
            ', '.join([str(index) for index in withdrawals_data]),
            tx_hash,
        )


def _get_withdrawal_data(
    validators: list[ConsensusValidator], withdrawals_amount: int
) -> dict[HexStr, int]:
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
    validators_manager_signature: bytes,
    harvest_params: HarvestParams | None,
    current_fee: Gwei,
) -> HexStr | None:
    """Sends withdrawValidators transaction to vault contract"""
    logger.info('Submitting withdrawValidators transaction')
    vault_contract = VaultContract(vault_address)

    if harvest_params is not None:
        # add update state calls before validator registration
        calls = [vault_contract.get_update_state_call(harvest_params)]
    else:
        # aggregate all the calls into one multicall
        calls = []

    calls.append(
        vault_contract.encode_abi(
            fn_name='withdrawValidators',
            args=[validators, validators_manager_signature],
        )
    )

    try:
        tx = await vault_contract.functions.multicall(calls).transact(
            {'value': Web3.to_wei(current_fee, 'gwei')}
        )
    except Exception as e:
        logger.info('Failed to withdrawal validators: %s', format_error(e))
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.info('withdrawValidators transaction failed')
        return None
    return Web3.to_hex(tx)
