import logging
from typing import Sequence

from eth_typing import HexStr
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.exceptions import ContractLogicError
from web3.types import Gwei

from src.common.clients import execution_client
from src.common.contracts import VaultContract
from src.common.execution import build_gas_manager, transaction_gas_wrapper
from src.common.typings import HarvestParams, OraclesApproval
from src.common.utils import format_error
from src.config.settings import settings
from src.validators.signing.common import encode_tx_validator_list
from src.validators.typings import Validator

logger = logging.getLogger(__name__)


# pylint: disable=too-many-arguments,too-many-locals
async def register_validators(
    approval: OraclesApproval,
    validators: Sequence[Validator],
    harvest_params: HarvestParams | None,
    validators_registry_root: Bytes32,
    validators_manager_signature: HexStr,
) -> HexStr | None:
    tx_validators = [
        Web3.to_bytes(tx_validator)
        for tx_validator in encode_tx_validator_list(
            validators=validators,
        )
    ]
    vault_contract = VaultContract(settings.vault)
    if harvest_params is not None:
        # add update state calls before validator registration
        calls = [vault_contract.get_update_state_call(harvest_params)]
    else:
        # aggregate all the calls into one multicall
        calls = []

    keeper_approval_params = (
        validators_registry_root,
        approval.deadline,
        b''.join(tx_validators),
        approval.signatures,
        approval.ipfs_hash,
    )

    # add validators registration call
    calls.append(
        vault_contract.encode_abi(
            fn_name='registerValidators',
            args=[keeper_approval_params, validators_manager_signature],
        )
    )

    logger.info('Submitting registration transaction')
    try:
        await vault_contract.functions.multicall(calls).estimate_gas()
    except (ValueError, ContractLogicError) as e:
        logger.error(
            'Failed to register validator(s): %s. '
            'Most likely registry root has changed during validators registration. Retrying...',
            format_error(e),
        )
        if settings.verbose:
            logger.exception(e)
        return None

    try:
        gas_manager = build_gas_manager()
        tx_params = await gas_manager.get_high_priority_tx_params()
        tx = await vault_contract.functions.multicall(calls).transact(tx_params)
    except Exception as e:
        logger.error('Failed to register validator(s): %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Registration transaction failed')
        return None

    return tx_hash


async def fund_validators(
    validators: list[Validator],
    validators_manager_signature: HexStr,
    harvest_params: HarvestParams | None,
) -> HexStr | None:
    tx_validators = [
        Web3.to_bytes(tx_validator)
        for tx_validator in encode_tx_validator_list(
            validators=validators,
        )
    ]
    calls = []
    vault_contract = VaultContract(settings.vault)
    if harvest_params is not None:
        # add update state calls before validator funding
        calls.append(vault_contract.get_update_state_call(harvest_params))
    fund_validators_call = vault_contract.encode_abi(
        fn_name='fundValidators',
        args=[b''.join(tx_validators), validators_manager_signature],
    )
    calls.append(fund_validators_call)

    logger.info('Submitting fund validators transaction')
    try:
        tx_function = vault_contract.functions.multicall(calls)
        tx = await transaction_gas_wrapper(tx_function=tx_function)
    except Exception as e:
        logger.error('Failed to fund validator(s): %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Funding transaction failed')
        return None

    return tx_hash


async def submit_consolidate_validators(
    validators: bytes,
    oracle_signatures: bytes | None,
    tx_fee: Gwei,
    validators_manager_signature: HexStr,
) -> HexStr | None:
    """Sends consolidate validators transaction to vault contract"""
    logger.info('Submitting consolidate validators transaction')
    vault_contract = VaultContract(settings.vault)

    if oracle_signatures is None:
        oracle_signatures = b''

    try:
        tx = await vault_contract.functions.consolidateValidators(
            validators,
            Web3.to_bytes(hexstr=validators_manager_signature),
            oracle_signatures,
        ).transact({'value': Web3.to_wei(tx_fee, 'gwei')})
    except Exception as e:
        logger.info('Failed to submit consolidate validators transaction: %s', format_error(e))
        return None

    logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx))
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.info('Consolidate validators transaction failed')
        return None
    return Web3.to_hex(tx)
