import logging
from typing import Sequence

from eth_typing import ChecksumAddress, HexStr
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.exceptions import ContractLogicError

from src.common.clients import execution_client
from src.common.contracts import VaultContract, multicall_contract
from src.common.execution import build_gas_manager
from src.common.typings import HarvestParams, OraclesApproval
from src.common.utils import format_error
from src.config.settings import settings
from src.harvest.execution import get_update_state_calls
from src.validators.signing.common import encode_tx_validator_list
from src.validators.typings import Validator

logger = logging.getLogger(__name__)


# pylint: disable=too-many-arguments,too-many-locals
async def register_validators(
    vault_address: ChecksumAddress,
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
            vault_address=vault_address,
        )
    ]
    if harvest_params is not None:
        # add update state calls before validator registration
        calls = await get_update_state_calls(
            vault_address=vault_address, harvest_params=harvest_params
        )
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
    if len(tx_validators) == 1:
        validators_registration_call = _get_single_validator_registration_call(
            vault_address=vault_address,
            keeper_approval_params=keeper_approval_params,
            validators_manager_signature=validators_manager_signature,
        )
    else:
        validators_registration_call = _get_multiple_validators_registration_call(
            vault_address=vault_address,
            keeper_approval_params=keeper_approval_params,
            validators_manager_signature=validators_manager_signature,
        )

    calls.append(validators_registration_call)

    logger.info('Submitting registration transaction')
    try:
        await multicall_contract.functions.aggregate(calls).estimate_gas()
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
        tx = await multicall_contract.functions.aggregate(calls).transact(tx_params)
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


# pylint: disable=too-many-arguments,too-many-locals
async def fund_validators(
    vault_address: ChecksumAddress,
    validators: list[Validator],
    validators_manager_signature: HexStr | None,
    harvest_params: HarvestParams | None,
) -> HexStr | None:
    tx_validators = [
        Web3.to_bytes(tx_validator)
        for tx_validator in encode_tx_validator_list(
            validators=validators,
            vault_address=vault_address,
        )
    ]
    if harvest_params is not None:
        # add update state calls before validator registration
        calls = await get_update_state_calls(
            vault_address=vault_address, harvest_params=harvest_params
        )
    else:
        # aggregate all the calls into one multicall
        calls = []
    vault_contract = VaultContract(vault_address)
    fund_validators_call = vault_contract.contract_address, vault_contract.encode_abi(
        fn_name='fundValidators',
        args=[tx_validators, Web3.to_bytes(hexstr=validators_manager_signature)],
    )
    calls.append(fund_validators_call)

    logger.info('Submitting fund validators transaction')
    try:
        await multicall_contract.functions.aggregate(calls).estimate_gas()
    except (ValueError, ContractLogicError) as e:
        logger.error(
            'Failed to fund validator(s): %s. Retrying...',
            format_error(e),
        )
        if settings.verbose:
            logger.exception(e)
        return None

    try:
        gas_manager = build_gas_manager()
        tx_params = await gas_manager.get_high_priority_tx_params()
        tx = await multicall_contract.functions.aggregate(calls).transact(tx_params)
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
        logger.error('Registration transaction failed')
        return None

    return tx_hash


def _get_single_validator_registration_call(
    vault_address: ChecksumAddress,
    keeper_approval_params: tuple,
    validators_manager_signature: HexStr | None,
) -> tuple[ChecksumAddress, HexStr]:
    vault_contract = VaultContract(vault_address)
    return vault_address, vault_contract.encode_abi(
        fn_name='registerValidators',
        args=[keeper_approval_params, Web3.to_bytes(hexstr=validators_manager_signature)],
    )


def _get_multiple_validators_registration_call(
    vault_address: ChecksumAddress,
    keeper_approval_params: tuple,
    validators_manager_signature: HexStr | None,
) -> tuple[ChecksumAddress, HexStr]:
    vault_contract = VaultContract(vault_address)
    return vault_address, vault_contract.encode_abi(
        fn_name='registerValidators',
        args=[keeper_approval_params, Web3.to_bytes(hexstr=validators_manager_signature)],
    )
