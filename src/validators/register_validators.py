import logging
from typing import Sequence

from eth_typing import ChecksumAddress, HexStr
from multiproof import MultiProof
from sw_utils.typings import Bytes32
from web3 import Web3

from src.common.contracts import (
    deposit_data_registry_contract,
    multicall_contract,
    vault_contract,
    vault_v1_contract,
)
from src.common.transaction import transact_checked
from src.common.typings import HarvestParams, OraclesApproval
from src.config.settings import settings
from src.harvest.execution import get_update_state_calls
from src.validators.signing.common import encode_tx_validator_list
from src.validators.typings import Validator

logger = logging.getLogger(__name__)


# pylint: disable=too-many-arguments,too-many-locals
async def register_validators(
    approval: OraclesApproval,
    multi_proof: MultiProof | None,
    validators: Sequence[Validator],
    harvest_params: HarvestParams | None,
    validators_registry_root: Bytes32,
    validators_manager_signature: HexStr | None,
) -> HexStr | None:
    tx_validators = [
        Web3.to_bytes(tx_validator) for tx_validator in encode_tx_validator_list(validators)
    ]
    if harvest_params is not None:
        # add update state calls before validator registration
        calls = await get_update_state_calls(harvest_params)
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
    vault_version = await vault_contract.version()
    if len(tx_validators) == 1:
        validators_registration_call = _get_single_validator_registration_call(
            vault_version=vault_version,
            keeper_approval_params=keeper_approval_params,
            multi_proof=multi_proof,
            validators_manager_signature=validators_manager_signature,
        )
    else:
        validators_registration_call = _get_multiple_validators_registration_call(
            vault_version=vault_version,
            keeper_approval_params=keeper_approval_params,
            multi_proof=multi_proof,
            validators_manager_signature=validators_manager_signature,
        )

    calls.append(validators_registration_call)

    # Simulate (estimate_gas) and send transaction with high-priority fees.
    logger.info('Submitting registration transaction')
    tx_receipt = await transact_checked(
        multicall_contract.functions.aggregate(calls),
        contract=multicall_contract,
        action='register validator(s)',
        high_priority=True,
        estimate_gas=True,
        revert_hint=(
            ' Most likely registry root has changed during validators registration. Retrying...'
        ),
    )
    if tx_receipt is None:
        return None

    return Web3.to_hex(tx_receipt['transactionHash'])


def _get_single_validator_registration_call(
    vault_version: int,
    keeper_approval_params: tuple,
    multi_proof: MultiProof | None,
    validators_manager_signature: HexStr | None,
) -> tuple[ChecksumAddress, HexStr]:
    if validators_manager_signature:
        return vault_contract.address, vault_contract.encode_abi(
            fn_name='registerValidators',
            args=[keeper_approval_params, Web3.to_bytes(hexstr=validators_manager_signature)],
        )

    if multi_proof is None:
        raise RuntimeError('multi_proof required')

    if vault_version == 1:
        return vault_v1_contract.address, vault_v1_contract.encode_abi(
            fn_name='registerValidator', args=[keeper_approval_params, multi_proof.proof]
        )

    return deposit_data_registry_contract.address, deposit_data_registry_contract.encode_abi(
        fn_name='registerValidator',
        args=[settings.vault, keeper_approval_params, multi_proof.proof],
    )


def _get_multiple_validators_registration_call(
    vault_version: int,
    keeper_approval_params: tuple,
    multi_proof: MultiProof | None,
    validators_manager_signature: HexStr | None,
) -> tuple[ChecksumAddress, HexStr]:
    if validators_manager_signature:
        return vault_contract.address, vault_contract.encode_abi(
            fn_name='registerValidators',
            args=[keeper_approval_params, Web3.to_bytes(hexstr=validators_manager_signature)],
        )

    if multi_proof is None:
        raise RuntimeError('multi_proof required')

    deposit_data_indexes = [leaf[1] for leaf in multi_proof.leaves]
    leaf_indexes = _calc_leaf_indexes(deposit_data_indexes)

    if vault_version == 1:
        return vault_v1_contract.address, vault_v1_contract.encode_abi(
            fn_name='registerValidators',
            args=[
                keeper_approval_params,
                leaf_indexes,
                multi_proof.proof_flags,
                multi_proof.proof,
            ],
        )

    return deposit_data_registry_contract.address, deposit_data_registry_contract.encode_abi(
        fn_name='registerValidators',
        args=[
            settings.vault,
            keeper_approval_params,
            leaf_indexes,
            multi_proof.proof_flags,
            multi_proof.proof,
        ],
    )


def _calc_leaf_indexes(deposit_data_indexes: list[int]) -> list[int]:
    if not deposit_data_indexes:
        return []

    sorted_indexes = sorted(deposit_data_indexes)
    return [deposit_data_indexes.index(index) for index in sorted_indexes]
