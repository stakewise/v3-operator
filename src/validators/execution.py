import logging
from typing import Sequence

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.exceptions import ContractCustomError
from web3.types import Wei

from src.common.contracts import VaultContract
from src.common.transaction import transact_checked
from src.common.typings import HarvestParams, OraclesApproval
from src.config.settings import settings
from src.validators.signing.common import encode_tx_validator_list
from src.validators.typings import Validator

logger = logging.getLogger(__name__)


async def tx_register_validators(
    approval: OraclesApproval,
    validators: Sequence[Validator],
    harvest_params: HarvestParams | None,
    validators_registry_root: HexStr,
    validators_manager_signature: HexStr,
) -> HexStr | None:
    # Get update state call if harvest params are provided
    vault_contract = VaultContract(settings.vault)
    if harvest_params is not None:
        calls = [vault_contract.get_update_state_call(harvest_params)]
    else:
        calls = []

    # Build keeper approval params
    tx_validators = [
        Web3.to_bytes(tx_validator)
        for tx_validator in encode_tx_validator_list(
            validators=validators,
        )
    ]
    keeper_approval_params = (
        Bytes32(Web3.to_bytes(hexstr=validators_registry_root)),
        approval.deadline,
        b''.join(tx_validators),
        approval.signatures,
        approval.ipfs_hash,
    )

    # add validators registration call
    calls.append(
        vault_contract.encode_abi(
            fn_name='registerValidators',
            args=[keeper_approval_params, Web3.to_bytes(hexstr=validators_manager_signature)],
        )
    )

    # Simulate (estimate_gas) and send transaction with high-priority fees.
    logger.info('Submitting registration transaction')
    tx_receipt = await transact_checked(
        vault_contract.functions.multicall(calls),
        contract=vault_contract,
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


async def tx_fund_validators(
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
        args=[b''.join(tx_validators), Web3.to_bytes(hexstr=validators_manager_signature)],
    )
    calls.append(fund_validators_call)

    logger.info('Submitting fund validators transaction')
    tx_function = vault_contract.functions.multicall(calls)
    tx_receipt = await transact_checked(
        tx_function,
        contract=vault_contract,
        action='fund validator(s)',
    )
    if tx_receipt is None:
        return None

    return Web3.to_hex(tx_receipt['transactionHash'])


async def get_withdrawable_assets(
    vault: ChecksumAddress,
    harvest_params: HarvestParams | None = None,
    block_number: BlockNumber | None = None,
) -> Wei:
    """Fetches vault's available assets for staking."""
    vault_contract = VaultContract(vault)
    if harvest_params is None:
        return await vault_contract.functions.withdrawableAssets().call(
            block_identifier=block_number
        )

    calls = [
        vault_contract.get_update_state_call(harvest_params),
        vault_contract.encode_abi(fn_name='withdrawableAssets', args=[]),
    ]
    try:
        multicall_response = await vault_contract.functions.multicall(calls).call()
    except ContractCustomError as e:
        reason = vault_contract.decode_custom_error(str(e.data)) or e.data
        logger.error('Failed to fetch withdrawable assets: execution reverted with %s', reason)
        raise

    return Wei(Web3.to_int(multicall_response[-1]))


async def tx_consolidate_validators(
    validators: bytes,
    oracle_signatures: bytes | None,
    tx_fee: Wei,
    validators_manager_signature: HexStr,
) -> HexStr | None:
    """Sends consolidate validators transaction to vault contract"""
    logger.info('Submitting consolidate validators transaction')
    vault_contract = VaultContract(settings.vault)

    if oracle_signatures is None:
        oracle_signatures = b''

    tx_function = vault_contract.functions.consolidateValidators(
        validators,
        Web3.to_bytes(hexstr=validators_manager_signature),
        oracle_signatures,
    )
    tx_receipt = await transact_checked(
        tx_function,
        contract=vault_contract,
        action='consolidate validator(s)',
        tx_params={'value': tx_fee},
    )
    if tx_receipt is None:
        return None
    return Web3.to_hex(tx_receipt['transactionHash'])
