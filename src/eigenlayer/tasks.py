import logging
from collections import defaultdict

from sw_utils import InterruptHandler, ValidatorStatus
from sw_utils.consensus import EXITED_STATUSES
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, HexStr

from src.common.checks import wait_execution_catch_up_consensus
from src.common.clients import execution_client
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import EigenPodOwnerContract, vault_restaking_contract
from src.common.eigenlayer_contracts import (
    BeaconChainOracleContract,
    DelayedWithdrawalRouterContract,
    EigenPodContract,
    delegation_manager_contract,
    eigenpod_manager_contract,
)
from src.common.execution import check_gas_price
from src.common.tasks import BaseTask
from src.common.utils import calc_slot_by_block_number
from src.config.settings import VALIDATORS_WITHDRAWALS_CHUNK_SIZE, settings
from src.eigenlayer.execution import (
    get_validator_withdrawals_chunk,
    submit_multicall_transaction,
)
from src.eigenlayer.generator import ProofsGenerationWrapper
from src.eigenlayer.typings import Validator
from src.eigenlayer.validators import get_vault_validators

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
        # filter by statuses???

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
        from_block = await self._get_start_block(current_block=current_block)

        vault_validators = await get_vault_validators(current_block)
        pods = await vault_restaking_contract.get_eigen_pods()
        pod_to_owner = await vault_restaking_contract.get_eigen_pod_owners(to_block=current_block)
        beacon_oracle_slot = await get_beacon_oracle_slot(block_number)
        calls = []
        exiting_validators_calls = await self._get_exiting_validator_calls(
            vault_validators=vault_validators,
            block_number=current_block,
            pod_to_owner=pod_to_owner,
        )

        withdrawals_calls = await self._get_withdrawals_calls(
            vault_validators=vault_validators,
            block_number=current_block,
            pod_to_owner=pod_to_owner,
            beacon_oracle_slot=beacon_oracle_slot,
        )

        delayed_withdrawals_calls = await self._get_delayed_withdrawals_calls(
            vault_validators=vault_validators,
            block_number=current_block,
            pod_to_owner=pod_to_owner,
        )

        complete_withdrawals_calls = await self._get_complete_withdrawals_calls(
            vault_validators=vault_validators,
            block_number=current_block,
            pod_to_owner=pod_to_owner,
        )

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
        logger.info('Successfully harvested vault')

    async def _get_start_block(
        self, current_block: BlockNumber, pods: list[ChecksumAddress]
    ) -> BlockNumber:
        '''
        :return:
        '''
        from_block = ...
        # exiting_validator_calls

        # can save exited validators?
        events = []

        exiting_validator_event = (
            await delegation_manager_contract.get_last_withdrawal_queued_event(
                from_block=from_block, to_block=current_block
            )
        )
        events.append(exiting_validator_event)

        # get_withdrawals_calls
        for pod in pods:
            partial_withdrawal_redeemed_event = await EigenPodContract(
                pod
            ).get_last_partial_withdrawal_redeemed_event(
                from_block=from_block, to_block=current_block
            )
            full_withdrawal_redeemed_event = await EigenPodContract(
                pod
            ).get_last_full_withdrawal_redeemed_event(from_block=from_block, to_block=current_block)
            events.append(partial_withdrawal_redeemed_event)
            events.append(full_withdrawal_redeemed_event)

        # _get_delayed_withdrawals_calls
        for pod in pods:
            last_pod_shares_updated_event = (
                await eigenpod_manager_contract.get_last_pod_shares_updated_event(
                    pod_owner=pod.owner, from_block=from_block, to_block=current_block
                )
            )
            events.append(last_pod_shares_updated_event)

        # # _get_complete_withdrawals_calls
        # last_withdrawal_queued_event = (
        #     await delegation_manager_contract.get_last_withdrawal_queued_event(
        #         from_block=from_block, to_block=current_block
        #     )
        # )
        # events.append(exiting_validator_event)

        if events:
            return BlockNumber(min([event['blockNumber'] for event in events if event]))
        return from_block

    async def _get_exiting_validator_calls(
        self,
        vault_validators: list[Validator],
        block_number: BlockNumber,
        pod_to_owner: dict[ChecksumAddress, ChecksumAddress],
    ) -> list[tuple[ChecksumAddress, bool, HexStr]]:
        '''
        For every validator that is in exiting or higher state, we must call
        https://github.com/stakewise/v3-core/blob/eigenlayer/contracts/vaults/ethereum/restake/EigenPodOwner.sol#L135.
        The shares argument must be the sum of effective balances.
        The effective balances should be fetched using
        https://github.com/Layr-Labs/eigenlayer-contracts/blob/
        v0.2.5-mainnet-m2-minor-eigenpod-upgrade/src/contracts/pods/EigenPod.sol#L806
        :return:
        '''
        # WithdrawalQueued event on queue_withdrawal

        statuses = [
            ValidatorStatus.ACTIVE_EXITING,
            ValidatorStatus.ACTIVE_SLASHED,
            *EXITED_STATUSES,
        ]
        exited_validators = [val for val in vault_validators if val.status in statuses]
        pod_to_shares = defaultdict(int)
        for validator in exited_validators:
            pod = validator.withdrawal_address
            validator_info = await EigenPodContract(pod).get_validator_pubkey_to_info(
                validator.public_key, block_number=block_number
            )
            pod_to_shares[pod] += validator_info.restaked_balance_gwei

        calls = []
        for pod, shares in pod_to_shares.items():
            call = await EigenPodOwnerContract(pod_to_owner[pod]).get_queue_withdrawal_call(shares)
            calls.append(call)

        return calls

    # pylint: disable-next=too-many-arguments
    async def _get_withdrawals_calls(
        self,
        vault_validators: list[Validator],
        from_block,
        current_block,
        pod_to_owner,
        beacon_oracle_slot,
    ) -> list[tuple[ChecksumAddress, bool, HexStr]]:
        '''
        For full and partial withdrawals of every validator, the operator must call
        https://github.com/stakewise/v3-core/blob/eigenlayer/contracts/vaults/ethereum/restake/EigenPodOwner.sol#L211.
        The inputs must be generated as in https://github.com/Layr-Labs/eigenpod-proofs-generation.
        '''
        # fetch withdrawals
        validators_indexes = {val.index for val in vault_validators}
        withdrawals_chunk = int(
            VALIDATORS_WITHDRAWALS_CHUNK_SIZE / settings.network_config.SECONDS_PER_BLOCK
        )
        withdrawals = []
        for block_number in range(from_block, current_block + 1, withdrawals_chunk):
            chunk = await get_validator_withdrawals_chunk(
                validators_indexes, from_block, current_block
            )
            withdrawals.extend(chunk)

        calls = []
        if not withdrawals:
            return calls

        last_slot = None
        with ProofsGenerationWrapper(
            slot=beacon_oracle_slot, chain_id=settings.network_config.CHAIN_ID
        ) as generator:
            for withdrawal in withdrawals:
                withdrawal.slot = await calc_slot_by_block_number(withdrawal.block_number)

                # clean up
                if last_slot and withdrawal.slot != last_slot:
                    generator.cleanup_withdrawals_slot_files(last_slot)

                data = await generator.generate_withdrawal_fields_proof(
                    withdrawals_slot=withdrawal.slot,
                    validator_index=withdrawal.validator_index,
                    withdrawal_index=withdrawal.index,
                )
                pod_owner = pod_to_owner[withdrawal.withdrawal_address]  # ?
                call = await EigenPodOwnerContract(
                    pod_owner
                ).get_verify_and_process_withdrawals_call(
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
                    withdrawal_fields=[data['validatorIndex']],
                    withdrawal_proofs=[data['validatorIndex']],
                    validator_fields_proofs=[
                        b''.join(
                            [Web3.to_bytes(hexstr=x) for x in data['WithdrawalCredentialProof']]
                        )
                    ],
                    validator_fields=[[Web3.to_bytes(hexstr=x) for x in data['ValidatorFields']]],
                )
                calls.append(call)
        return calls

    async def _get_delayed_withdrawals_calls(
        self, block_number, pod_to_owner
    ) -> list[tuple[ChecksumAddress, bool, HexStr]]:
        '''
        If there are any delayed withdrawals completed, call
        https://github.com/stakewise/v3-core/blob/eigenlayer/contracts/vaults/ethereum/restake/EigenPodOwner.sol#L189.
        You can fetch claimable delayed withdrawals with
        https://github.com/Layr-Labs/eigenlayer-contracts/blob/mainnet-deployment/src/contracts/interfaces/IDelayedWithdrawalRouter.sol#L46
        '''
        calls = []

        for pod in pod_to_owner.keys():
            delayed_withdrawal_router = await EigenPodContract(pod).get_delayed_withdrawal_router(
                block_number
            )
            delayed_withdrawals = await DelayedWithdrawalRouterContract(
                delayed_withdrawal_router
            ).get_claimable_user_delayed_withdrawals(
                pod, block_number=block_number
            )  # pod address?

            call = await EigenPodOwnerContract(
                [pod_to_owner[pod]]
            ).get_claim_delayed_withdrawals_call(max_number=len(delayed_withdrawals))
            calls.append(call)

        return calls

    async def _get_complete_withdrawals_calls(
        self, block_number, pod_to_owner
    ) -> list[tuple[ChecksumAddress, bool, HexStr]]:
        '''
        Keep track of all the queued withdrawals using WithdrawalQueued event:
        https://github.com/Layr-Labs/eigenlayer-contracts/blob/
        v0.2.5-mainnet-m2-minor-eigenpod-upgrade/src/contracts/interfaces/IDelegationManager.sol#L135.
        Mark withdrawal as undelegation=True if there is StakerUndelegated  or
        StakerForceUndelegated event in the same block as WithdrawalQueued event.
        For every withdrawal:
        Check whether it can be processed by checking that the current block is higher that
        withdrawal.startBlock + withdrawalsDelayBlocks . withdrawalsDelayBlocks  is calculated
        as max(minWithdrawalDelayBlocks, strategyWithdrawalDelayBlocks[0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0])
        can be fetched in https://github.com/Layr-Labs/eigenlayer-contr
        acts/blob/v0.2.5-mainnet-m2-minor-eigenpod-upgrade/
        src/contracts/core/DelegationManagerStorage.sol#L85 and https://github.com/Layr-Labs/eigenlayer-contracts/blob/
         v0.2.5-mainnet-m2-minor-eigenpod-upgrade/src/contracts/interfaces/IDelegationManager.sol#L396
        If the withdrawal is undelegation , set receiveAsTokens=False , otherwise True .
        NB! When receiveAsTokens is True  the balance of the eigen pod must be >= that withdrawal.shares
        Clean up processed withdrawal
        '''
        from src.eigenlayer.database import WithdrawalsCrud

        crud = WithdrawalsCrud()
        ############
        # mark current queued withdrawals as completed
        # can be as scanner
        last_completed_withdrawals_block = WithdrawalsCrud().get_last_completed_withdrawals()
        if not last_completed_withdrawals_block:
            last_completed_withdrawals_block = vault_creation_block

        complete_withdrawals = await delegation_manager_contract.get_withdrawal_completed_events(
            from_block=last_completed_withdrawals_block,
            to_block=block_number,
        )
        uncomplited_withdrawals = crud.get_uncomplited_withdrawals()
        res = [
            item.withdrawal_root for item in complete_withdrawals if item in uncomplited_withdrawals
        ]
        WithdrawalsCrud().mask_as_completed(res)

        ############
        # fetch and store new
        # can be scanner - fetch withdrawals from db
        last_completed_withdrawals_block = WithdrawalsCrud().get_last_completed_withdrawals()
        queued_withdrawals_events = await delegation_manager_contract.get_withdrawal_queued_events(
            from_block=last_completed_withdrawals_block, to_block=block_number
        )
        queued_withdrawals = [
            e for e in queued_withdrawals_events if e.withdrawer in pod_to_owner.keys()
        ]
        if not queued_withdrawals:
            return []
        crud.save_queued_withdrawals(queued_withdrawals)
        # processing
        calls = []
        min_withdrawal_delay_blocks = (
            await delegation_manager_contract.get_min_withdrawal_delay_blocks()
        )
        strategy_withdrawal_delay_blocks = (
            await delegation_manager_contract.get_strategy_withdrawal_delay_blocks(
                '0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0'
            )
        )
        withdrawals_delay_blocks = max(
            min_withdrawal_delay_blocks, strategy_withdrawal_delay_blocks
        )
        staker_undelegated_events = (
            await delegation_manager_contract.get_staker_undelegated_events()
        )
        staker_force_undelegated_events = (
            await delegation_manager_contract.get_staker_force_undelegated_events()
        )
        undelegated_blocks = {
            e.block_number for e in [*staker_undelegated_events, *staker_force_undelegated_events]
        }
        for withdrawal in queued_withdrawals:
            if withdrawal.block_number in undelegated_blocks:
                withdrawal.undelegation = True

            if block_number < withdrawal.start_block + withdrawals_delay_blocks:
                continue

            receive_as_tokens = True
            if withdrawal.undelegation:
                receive_as_tokens = False

            if receive_as_tokens:
                pod_balance = await execution_client.eth.get_balance(withdrawal)
                if pod_balance < withdrawal.shares:
                    logger.info('')
                    continue

            call = await EigenPodOwnerContract(
                pod_to_owner[withdrawal]
            ).get_complete_queued_withdrawal_call(
                delegated_to=withdrawal.delegated_to,
                nonce=withdrawal.nonce,
                shares=withdrawal.shares[0],
                start_block=withdrawal.start_block,
                receive_as_tokens=receive_as_tokens,
            )

            calls.append(call)

        return calls


async def get_beacon_oracle_slot(block_number: BlockNumber) -> int | None:
    beacon_oracle = await eigenpod_manager_contract.get_beacon_chain_oracle()
    event = await BeaconChainOracleContract(beacon_oracle).get_last_oracle_update_event(
        from_block=1, to_block=block_number
    )
    if event:
        return event['args']['slot']
