import logging

from sw_utils import InterruptHandler
from web3 import Web3
from web3.types import BlockNumber

from src.common.checks import wait_execution_catch_up_consensus
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import EigenPodOwnerContract, vault_restaking_contract
from src.common.execution import check_gas_price
from src.common.tasks import BaseTask
from src.config.settings import settings
from src.eigenlayer.contracts import (
    BeaconChainOracleContract,
    EigenPodContract,
    eigenpod_manager_contract,
)
from src.eigenlayer.database import WithdrawalCheckpointsCrud
from src.eigenlayer.execution import submit_multicall_transaction
from src.eigenlayer.generator import ProofsGenerationWrapper
from src.eigenlayer.validators import get_vault_validators
from src.eigenlayer.withdrawals import (
    CompleteWithdrawalsProcessor,
    DelayedWithdrawalsProcessor,
    ExitingValidatorsProcessor,
    WithdrawalsProcessor,
)

logger = logging.getLogger(__name__)


class EigenlayerValidatorsTask(BaseTask):
    # pylint: disable-next=too-many-locals
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """Process restaking vault validators withdrawals if needed."""
        # check current gas prices
        if not await check_gas_price():
            return
        chain_state = await get_chain_finalized_head()

        block_number = chain_state.execution_block
        vault_validators = await get_vault_validators(block_number)

        # scan eigenpod ValidatorRestaked events
        registered_indexes = []
        pods = await vault_restaking_contract.get_eigen_pods()
        for pod in pods:
            pod_indexes = await EigenPodContract(pod).get_validator_restaked_indexes(
                to_block=block_number
            )
            registered_indexes.extend(pod_indexes)
        unregistered_validators = [
            validator for validator in vault_validators if validator.index not in registered_indexes
        ]
        if not unregistered_validators:
            return
        calls = []
        pod_to_owner = await vault_restaking_contract.get_eigen_pod_owners(to_block=block_number)

        slot = await get_beacon_oracle_slot(block_number=block_number)
        for validator in unregistered_validators:
            # register in eigenlayer
            pod = validator.withdrawal_address
            data = await ProofsGenerationWrapper(
                slot=slot, chain_id=settings.network_config.CHAIN_ID
            ).generate_withdrawal_credentials(validator_index=validator.index)
            # process data
            call = await EigenPodOwnerContract(
                pod_to_owner[pod]
            ).get_verify_withdrawal_credentials_call(
                oracle_timestamp=int(data['oracleTimestamp']),
                state_root_proof=(
                    Web3.to_bytes(hexstr=data['beaconStateRoot']),
                    b''.join(
                        [
                            Web3.to_bytes(hexstr=x)
                            for x in data['StateRootAgainstLatestBlockHeaderProof']
                        ]
                    ),
                ),
                validator_indices=[data['validatorIndex']],
                validator_fields_proofs=[
                    b''.join([Web3.to_bytes(hexstr=x) for x in data['WithdrawalCredentialProof']])
                ],
                validator_fields=[[Web3.to_bytes(hexstr=x) for x in data['ValidatorFields']]],
            )
            calls.append(call)

        logger.info('Submitting harvest transaction...')
        tx_hash = await submit_multicall_transaction(
            [
                *calls,
            ]
        )
        if not tx_hash:
            return
        logger.info('Successfully harvested vault')


class EigenlayerWithdrawalsTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """Process restaking vault validators withdrawals if needed."""

        # check current gas prices
        if not await check_gas_price():
            return

        chain_state = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(
            chain_state=chain_state, interrupt_handler=interrupt_handler
        )
        current_block = chain_state.execution_block

        vault_validators = await get_vault_validators(current_block)
        pod_to_owner = await vault_restaking_contract.get_eigen_pod_owners(to_block=current_block)
        beacon_oracle_slot = await get_beacon_oracle_slot(current_block)

        exiting_validators_calls = await ExitingValidatorsProcessor(
            pod_to_owner=pod_to_owner,
            block_number=current_block,
        ).get_contact_calls(
            vault_validators=vault_validators,
        )
        withdrawals_calls = await WithdrawalsProcessor(
            pod_to_owner=pod_to_owner,
            block_number=current_block,
        ).get_contact_calls(
            vault_validators=vault_validators,
            beacon_oracle_slot=beacon_oracle_slot,
        )

        delayed_withdrawals_calls = await DelayedWithdrawalsProcessor(
            pod_to_owner=pod_to_owner,
            block_number=current_block,
        ).get_contact_calls()

        (
            complete_withdrawals_calls,
            completed_withdrawals_block,
        ) = await CompleteWithdrawalsProcessor(
            pod_to_owner=pod_to_owner,
            block_number=current_block,
        ).get_contact_calls()

        logger.info('Starting vault harvest')
        logger.info('Submitting harvest transaction...')

        tx_hash = await submit_multicall_transaction(
            [
                *exiting_validators_calls,
                *withdrawals_calls,
                *delayed_withdrawals_calls,
                *complete_withdrawals_calls,
            ]
        )
        if not tx_hash:
            return
        if completed_withdrawals_block:
            WithdrawalCheckpointsCrud().save_last_completed_withdrawals_block_number(
                completed_withdrawals_block
            )

        logger.info('Successfully harvested vault')


async def get_beacon_oracle_slot(block_number: BlockNumber) -> int:
    beacon_oracle = await eigenpod_manager_contract.get_beacon_chain_oracle(block_number)
    event = await BeaconChainOracleContract(beacon_oracle).get_last_oracle_update_event(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK, to_block=block_number
    )
    if not event:
        raise ValueError('Can not find Eigenlayer beacon oracle slot')
    return event['args']['slot']
