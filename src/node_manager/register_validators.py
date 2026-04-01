import logging
from typing import Sequence

from eth_typing import ChecksumAddress, HexStr
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.exceptions import ContractLogicError
from web3.types import Gwei

from src.common.clients import execution_client
from src.common.contracts import nodes_manager_contract, validators_registry_contract
from src.common.execution import build_gas_manager, transaction_gas_wrapper
from src.common.utils import format_error
from src.config.settings import settings
from src.node_manager.typings import NodeManagerRegistrationOraclesApproval
from src.validators.execution import get_validators_start_index
from src.validators.signing.common import encode_tx_validator_list
from src.validators.typings import Validator

logger = logging.getLogger(__name__)


# pylint: disable=too-many-locals
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
    signatures = b''.join(Web3.to_bytes(hexstr=s) for s in approval.signatures)
    keeper_params = (
        Bytes32(Web3.to_bytes(hexstr=validators_registry_root)),
        approval.deadline,
        b''.join(tx_validators),
        b''.join(Web3.to_bytes(hexstr=s) for s in approval.keeper_signatures),
        approval.ipfs_hash,
    )

    logger.info('Submitting community vault validator registration transaction')

    try:
        await nodes_manager_contract.functions.registerValidators(
            operator_address, keeper_params, signatures
        ).estimate_gas()
    except (ValueError, ContractLogicError) as e:
        logger.error('Failed to register community vault validator(s): %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    try:
        gas_manager = build_gas_manager()
        tx_params = await gas_manager.get_high_priority_tx_params()
        tx = await nodes_manager_contract.functions.registerValidators(
            operator_address, keeper_params, signatures
        ).transact(tx_params)
    except Exception as e:
        logger.error('Failed to register community vault validator(s): %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info(
        'Waiting for register community vault validator(s) transaction %s confirmation', tx_hash
    )
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Register community vault validator(s) transaction failed')
        return None

    return tx_hash


async def fund_validators(
    operator_address: ChecksumAddress,
    signatures: list[HexStr],
    validator_fundings: dict[HexStr, Gwei],
) -> HexStr | None:
    """Submit fundValidators transaction to NodesManager contract."""
    validators = [
        Validator(
            public_key=public_key,
            amount=amount,
            deposit_signature=HexStr(Web3.to_hex(bytes(96))),
        )
        for public_key, amount in validator_fundings.items()
    ]
    tx_validators = [
        Web3.to_bytes(tx_validator)
        for tx_validator in encode_tx_validator_list(validators=validators)
    ]
    validators_bytes = b''.join(tx_validators)
    signatures_bytes = b''.join(Web3.to_bytes(hexstr=s) for s in signatures)

    logger.info('Submitting community vault validator funding transaction')

    try:
        tx_function = nodes_manager_contract.functions.fundValidators(
            operator_address, validators_bytes, signatures_bytes
        )
        tx = await transaction_gas_wrapper(tx_function)
    except Exception as e:
        logger.error('Failed to fund community vault validator(s): %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    logger.info(
        'Waiting for fund community vault validator(s) transaction %s confirmation', tx_hash
    )
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Fund community vault validator(s) transaction failed')
        return None

    return tx_hash
