import logging

from eth_typing import ChecksumAddress, HexStr
from multiproof import MultiProof
from sw_utils.typings import Bytes32
from web3 import Web3

from src.common.clients import execution_client
from src.common.contracts import (
    deposit_data_registry_contract,
    multicall_contract,
    vault_contract,
    vault_v1_contract,
)
from src.common.execution import get_high_priority_tx_params
from src.common.typings import HarvestParams, OraclesApproval
from src.common.utils import format_error
from src.config.networks import GNO_NETWORKS
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def _get_update_state_calls(
    harvest_params: HarvestParams,
) -> list[tuple[ChecksumAddress, HexStr]]:
    calls = []
    if settings.network in GNO_NETWORKS:
        # TODO: add swap xDAI to GNO to calls if it passes static call
        pass

    calls.append(
        (
            vault_contract.address,
            vault_contract.encode_abi(
                fn_name='updateState',
                args=[
                    (
                        harvest_params.rewards_root,
                        harvest_params.reward,
                        harvest_params.unlocked_mev_reward,
                        harvest_params.proof,
                    )
                ],
            ),
        )
    )
    return calls


def _get_single_validator_registration_call(
    vault_version: int,
    keeper_approval_params: tuple,
    multi_proof: MultiProof | None,
    validators_manager_signature: HexStr | None,
) -> tuple[ChecksumAddress, HexStr]:
    if validators_manager_signature:
        return vault_contract.address, vault_contract.encode_abi(
            fn_name='registerValidators',
            args=[keeper_approval_params, validators_manager_signature],
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
            args=[keeper_approval_params, validators_manager_signature],
        )

    if multi_proof is None:
        raise RuntimeError('multi_proof required')

    proof_indexes = [leaf[1] for leaf in multi_proof.leaves]

    if vault_version == 1:
        return vault_v1_contract.address, vault_v1_contract.encode_abi(
            fn_name='registerValidators',
            args=[
                keeper_approval_params,
                proof_indexes,
                multi_proof.proof_flags,
                multi_proof.proof,
            ],
        )

    return deposit_data_registry_contract.address, deposit_data_registry_contract.encode_abi(
        fn_name='registerValidators',
        args=[
            settings.vault,
            keeper_approval_params,
            proof_indexes,
            multi_proof.proof_flags,
            multi_proof.proof,
        ],
    )


# pylint: disable=too-many-arguments
async def register_validators(
    approval: OraclesApproval,
    multi_proof: MultiProof | None,
    tx_validators: list[bytes],
    harvest_params: HarvestParams | None,
    validators_registry_root: Bytes32,
    validators_manager_signature: HexStr | None,
) -> HexStr | None:
    """Registers validators."""
    logger.info('Submitting registration transaction')

    if harvest_params is not None:
        # add update state calls before validator registration
        calls = await _get_update_state_calls(harvest_params)
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

    try:
        tx_params = await get_high_priority_tx_params()
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
