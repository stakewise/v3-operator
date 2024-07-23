import logging
from datetime import datetime, timezone

from sw_utils import InterruptHandler
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress

from src.common.app_state import AppState
from src.common.checks import wait_execution_catch_up_consensus
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import vault_restaking_contract
from src.common.execution import check_gas_price
from src.common.tasks import BaseTask
from src.config.settings import settings
from src.eigenlayer.contracts import (
    BeaconChainOracleContract,
    EigenPodContract,
    eigenpod_manager_contract,
)
from src.eigenlayer.database import CheckpointsCrud, CheckpointType
from src.eigenlayer.execution import (
    submit_multicall_transaction,
    submit_verify_withdrawal_credentials_transaction,
)
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
        """Verify validators withdrawal credentials in Eigenlayer if needed."""

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
        logger.info(
            'Verifying withdrawal credentials for %s validators...', len(unregistered_validators)
        )

        verify_data: dict[ChecksumAddress, dict] = {}
        pod_to_owner = await vault_restaking_contract.get_eigen_pod_owners(to_block=block_number)
        beacon_oracle_slot = await get_beacon_oracle_slot(block_number=block_number)
        with ProofsGenerationWrapper(
            slot=beacon_oracle_slot, chain_id=settings.network_config.CHAIN_ID
        ) as generator:
            for validator in unregistered_validators:
                pod = validator.withdrawal_address
                data = await generator.generate_withdrawal_credentials(
                    validator_index=validator.index
                )
                verify_data = self._update_verify_data(
                    verify_data=verify_data, validator_data=data, pod=pod
                )

        verified_indexes = []
        for pod, owner in pod_to_owner.items():
            logger.info(
                'Submitting eigenlayer verify withdrawal credentials transaction for pod %s...', pod
            )

            if verify_data.get(pod):
                tx_hash = await submit_verify_withdrawal_credentials_transaction(
                    owner, **verify_data[pod]
                )
                if tx_hash:
                    verified_indexes.extend(verify_data[pod]['validator_indices'])
        if verified_indexes:
            logger.info(
                'Successfully verified withdrawal credentials for %s validators',
                len(verified_indexes),
            )

    def _update_verify_data(
        self, verify_data: dict, validator_data: dict, pod: ChecksumAddress
    ) -> dict:
        """Process generated output data to contact call args format"""
        if verify_data.get(pod):
            verify_data[pod]['validator_indices'].append(validator_data['validatorIndex'])
            verify_data[pod]['validator_fields'].append(
                [Web3.to_bytes(hexstr=x) for x in validator_data['ValidatorFields']]
            )
            verify_data[pod]['validator_fields_proofs'].append(
                b''.join(
                    [Web3.to_bytes(hexstr=x) for x in validator_data['WithdrawalCredentialProof']]
                )
            )
        else:
            verify_data[pod] = {
                'oracle_timestamp': int(validator_data['oracleTimestamp']),
                'state_root_proof': (
                    Web3.to_bytes(hexstr=validator_data['beaconStateRoot']),
                    b''.join(
                        [
                            Web3.to_bytes(hexstr=x)
                            for x in validator_data['StateRootAgainstLatestBlockHeaderProof']
                        ]
                    ),
                ),
                'validator_indices': [validator_data['validatorIndex']],
                'validator_fields': [
                    [Web3.to_bytes(hexstr=x) for x in validator_data['ValidatorFields']]
                ],
                'validator_fields_proofs': [
                    b''.join(
                        [
                            Web3.to_bytes(hexstr=x)
                            for x in validator_data['WithdrawalCredentialProof']
                        ]
                    )
                ],
            }
        return verify_data


class EigenlayerWithdrawalsTask(BaseTask):
    # pylint: disable-next=too-many-locals
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        """Process restaking vault validators withdrawals if needed."""
        app_state = AppState()
        last_withdrawals_update_timestamp = app_state.last_withdrawals_update_timestamp
        now = int(datetime.now(timezone.utc).timestamp())
        if (
            last_withdrawals_update_timestamp
            and last_withdrawals_update_timestamp + settings.withdrawals_processing_interval > now
        ):
            return

        # check current gas prices
        if not await check_gas_price():
            return

        chain_state = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(
            chain_state=chain_state, interrupt_handler=interrupt_handler
        )
        logger.info('Starting Eigenlayer withdrawals processing...')
        current_block = chain_state.execution_block

        vault_validators = await get_vault_validators(current_block)
        pod_to_owner = await vault_restaking_contract.get_eigen_pod_owners(to_block=current_block)
        beacon_oracle_slot = await get_beacon_oracle_slot(current_block)

        calls = []
        logger.info('processing withdrawals...')
        withdrawals_calls = await WithdrawalsProcessor(
            pod_to_owner=pod_to_owner,
            block_number=current_block,
        ).get_contact_calls(
            vault_validators=vault_validators,
            beacon_oracle_slot=beacon_oracle_slot,
        )
        calls.extend(withdrawals_calls)

        logger.info('processing Eigenlayer delayed withdrawals...')

        delayed_withdrawals_calls = await DelayedWithdrawalsProcessor(
            pod_to_owner=pod_to_owner,
            block_number=current_block,
        ).get_contact_calls()
        calls.extend(delayed_withdrawals_calls)
        if calls:
            logger.info('Submitting multicall withdrawals transaction...')
            tx_hash = await submit_multicall_transaction(calls)
            if not tx_hash:
                return

        CheckpointsCrud().update_checkpoint_block_number(
            checkpoint_type=CheckpointType.COMPLETED,
            block_number=current_block,
        )
        logger.info('processing exiting validators...')
        await ExitingValidatorsProcessor(
            pod_to_owner=pod_to_owner,
            block_number=current_block,
        ).call(
            vault_validators=vault_validators,
        )

        logger.info('processing Eigenlayer queued withdrawals...')

        await CompleteWithdrawalsProcessor(
            pod_to_owner=pod_to_owner,
            block_number=current_block,
        ).call()

        app_state.last_withdrawals_update_timestamp = now
        logger.info('Successfully processed pod withdrawals')


async def get_beacon_oracle_slot(block_number: BlockNumber) -> int:
    beacon_oracle = await eigenpod_manager_contract.get_beacon_chain_oracle(block_number)
    event = await BeaconChainOracleContract(beacon_oracle).get_last_oracle_update_event(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK, to_block=block_number
    )
    if not event:
        raise ValueError('Can not find Eigenlayer beacon oracle slot')
    return event['args']['slot']
