import logging
from typing import Any, Sequence

from eth_typing import ChecksumAddress, HexStr
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.exceptions import ContractLogicError
from web3.types import Gwei

from src.common.clients import execution_client
from src.common.contracts import NodesManagerContract, validators_registry_contract
from src.common.execution import build_gas_manager
from src.common.utils import format_error
from src.config.settings import settings
from src.node_manager.typings import NodeManagerRegistrationOraclesApproval
from src.validators.execution import get_validators_start_index
from src.validators.signing.common import encode_tx_validator_list
from src.validators.typings import Validator

logger = logging.getLogger(__name__)


async def register_validators(
    operator_address: ChecksumAddress,
    approval: NodeManagerRegistrationOraclesApproval,
    validators: Sequence[Validator],
    validators_registry_root: HexStr,
    validator_index: int,
) -> HexStr | None:
    """Submit registerValidators transaction to NodesManager contract."""
    registry_root = await validators_registry_contract.get_registry_root()
    if registry_root != validators_registry_root:
        logger.info('Validators registry root has changed. Retrying...')
        return None

    current_validator_index = await get_validators_start_index()
    if current_validator_index != validator_index:
        logger.info('Validator index has changed. Retrying...')
        return None

    tx_validators = [
        Web3.to_bytes(tx_validator)
        for tx_validator in encode_tx_validator_list(validators=validators)
    ]
    keeper_params = (
        Bytes32(Web3.to_bytes(hexstr=validators_registry_root)),
        approval.deadline,
        b''.join(tx_validators),
        approval.keeper_signatures,
        approval.ipfs_hash,
    )

    logger.info('Submitting community vault registration transaction')
    return await _submit_tx(
        'registerValidators',
        (operator_address, keeper_params, approval.nm_signatures),
        'register community vault validator(s)',
    )


async def fund_validators(
    operator_address: ChecksumAddress,
    signatures: bytes,
    validator_fundings: dict[HexStr, Gwei],
) -> HexStr | None:
    """Submit fundValidators transaction to NodesManager contract."""
    empty_signature = Web3.to_hex(bytes(96))
    validators: list[Validator] = [
        Validator(
            public_key=public_key,
            deposit_signature=empty_signature,
            amount=amount,
        )
        for public_key, amount in validator_fundings.items()
    ]

    tx_validators = [
        Web3.to_bytes(tx_validator)
        for tx_validator in encode_tx_validator_list(validators=validators)
    ]
    encoded_validators = b''.join(tx_validators)

    logger.info(
        'Submitting community vault funding transaction for %d validator(s)', len(validators)
    )
    return await _submit_tx(
        'fundValidators',
        (operator_address, encoded_validators, signatures),
        'fund community vault validator(s)',
    )


async def _submit_tx(
    tx_function_name: str,
    tx_args: tuple[Any, ...],
    log_action: str,
) -> HexStr | None:
    """Estimate gas, submit transaction, and wait for confirmation."""
    nodes_manager_contract = NodesManagerContract(
        address=settings.network_config.COMMUNITY_VAULT_CONTRACT_ADDRESS
    )
    fn = getattr(nodes_manager_contract.functions, tx_function_name)

    try:
        await fn(*tx_args).estimate_gas()
    except (ValueError, ContractLogicError) as e:
        logger.error('Failed to %s: %s', log_action, format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    try:
        gas_manager = build_gas_manager()
        tx_params = await gas_manager.get_high_priority_tx_params()
        tx = await fn(*tx_args).transact(tx_params)
    except Exception as e:
        logger.error('Failed to %s: %s', log_action, format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info('Waiting for %s transaction %s confirmation', log_action, tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('%s transaction failed', log_action.capitalize())
        return None

    return tx_hash
