import logging
from collections import defaultdict

from sw_utils.consensus import ACTIVE_STATUSES
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, HexStr

from src.common.clients import execution_client
from src.common.consensus import get_chain_epoch_head
from src.common.contracts import EigenPodOwnerContract
from src.common.utils import calc_slot_by_block_number
from src.config.settings import VALIDATORS_WITHDRAWALS_CHUNK_SIZE, settings
from src.eigenlayer.contracts import (
    DelayedWithdrawalRouterContract,
    EigenPodContract,
    delegation_manager_contract,
    eigenpod_manager_contract,
)
from src.eigenlayer.database import CheckpointsCrud, CheckpointType
from src.eigenlayer.execution import (
    get_validator_withdrawals_chunk,
    submit_complete_queued_withdrawal_transaction,
    submit_queue_withdrawal_transaction,
)
from src.eigenlayer.generator import ProofsGenerationWrapper
from src.eigenlayer.typings import Validator

logger = logging.getLogger(__name__)


EIGENLAYER_DEFAULT_STRATEGY = Web3.to_checksum_address('0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0')


class WithdrawalsProcessor:
    def __init__(
        self, pod_to_owner: dict[ChecksumAddress, ChecksumAddress], block_number: BlockNumber
    ):
        self.block_number = block_number
        self.pod_to_owner = pod_to_owner

    # pylint: disable-next=too-many-locals
    async def get_contact_calls(
        self,
        vault_validators: list[Validator],
        beacon_oracle_slot: int,
    ) -> list[tuple[ChecksumAddress, HexStr]]:
        '''
        For full and partial withdrawals of every validator, the operator must call
        https://github.com/stakewise/v3-core/blob/main
        /contracts/vaults/ethereum/restake/EigenPodOwner.sol#L211.
        The inputs must be generated as
        in https://github.com/Layr-Labs/eigenpod-proofs-generation.
        '''
        if not vault_validators:
            return []

        from_block = await self._get_from_block(vault_validators)
        # fetch withdrawals
        validators_indexes = {val.index for val in vault_validators}
        withdrawals_chunk = int(
            VALIDATORS_WITHDRAWALS_CHUNK_SIZE / settings.network_config.SECONDS_PER_BLOCK
        )
        withdrawals = []
        for block_number in range(from_block, self.block_number + 1, withdrawals_chunk):
            chunk = await get_validator_withdrawals_chunk(
                indexes=validators_indexes,
                from_block=from_block,
                to_block=BlockNumber(min(block_number + withdrawals_chunk - 1, self.block_number)),
            )
            withdrawals.extend(chunk)

        verify_data: dict[ChecksumAddress, dict] = {}
        calls: list[tuple[ChecksumAddress, HexStr]] = []
        if not withdrawals:
            return calls

        last_slot = None
        with ProofsGenerationWrapper(
            slot=beacon_oracle_slot, chain_id=settings.network_config.CHAIN_ID
        ) as generator:
            for withdrawal in withdrawals:
                withdrawal.slot = await calc_slot_by_block_number(withdrawal.block_number)

                # clean up generator files
                if last_slot and withdrawal.slot != last_slot:
                    generator.cleanup_withdrawals_slot_files(last_slot)

                data = await generator.generate_withdrawal_fields_proof(
                    withdrawals_slot=withdrawal.slot,
                    validator_index=withdrawal.validator_index,
                    withdrawal_index=withdrawal.index,
                )
                verify_data = self._update_verify_data(
                    verify_data=verify_data, withdrawal_data=data, pod=withdrawal.withdrawal_address
                )
                last_slot = withdrawal.slot

        for pod, owner in self.pod_to_owner.items():
            if verify_data.get(pod):
                call = await EigenPodOwnerContract(owner).get_verify_and_process_withdrawals_call(
                    **verify_data[pod]
                )
                calls.append(call)

        return calls

    async def _get_from_block(self, vault_validators: list[Validator]) -> BlockNumber:
        from_block = CheckpointsCrud().get_checkpoint_block_number(CheckpointType.PARTIAL)
        if from_block:
            return BlockNumber(from_block + 1)

        events = []
        for pod in self.pod_to_owner.keys():
            partial_withdrawal_redeemed_event = await EigenPodContract(
                pod
            ).get_last_partial_withdrawal_redeemed_event(
                from_block=settings.network_config.KEEPER_GENESIS_BLOCK, to_block=self.block_number
            )
            if partial_withdrawal_redeemed_event:
                events.append(partial_withdrawal_redeemed_event)

            full_withdrawal_redeemed_event = await EigenPodContract(
                pod
            ).get_last_full_withdrawal_redeemed_event(
                from_block=settings.network_config.KEEPER_GENESIS_BLOCK, to_block=self.block_number
            )
            if full_withdrawal_redeemed_event:
                events.append(full_withdrawal_redeemed_event)
        if events:
            return BlockNumber(max(event['blockNumber'] for event in events if event))

        epoch = min(val.activation_epoch for val in vault_validators)
        chain_state = await get_chain_epoch_head(epoch)
        return chain_state.execution_block

    @staticmethod
    def _withdrawal_proofs(data):
        '''
        struct WithdrawalProof {
        bytes withdrawalProof; +
        bytes slotProof; +
        bytes executionPayloadProof; +
        bytes timestampProof; +
        bytes historicalSummaryBlockRootProof; + HistoricalSummaryProof
        uint64 blockRootIndex;  consensus
        uint64 historicalSummaryIndex; +
        uint64 withdrawalIndex; +
        bytes32 blockRoot; consensus
        bytes32 slotRoot; +
        bytes32 timestampRoot; +
        bytes32 executionPayloadRoot; +
        }
        '''

        return (
            _proof_to_bytes(data['WithdrawalProof']),
            _proof_to_bytes(data['SlotProof']),
            _proof_to_bytes(data['ExecutionPayloadProof']),
            _proof_to_bytes(data['TimestampProof']),
            _proof_to_bytes(data['HistoricalSummaryProof']),
            data['blockHeaderRootIndex'],
            data['historicalSummaryIndex'],
            data['withdrawalIndex'],
            Web3.to_bytes(hexstr=data['blockHeaderRoot']),
            Web3.to_bytes(hexstr=data['slotRoot']),
            Web3.to_bytes(hexstr=data['timestampRoot']),
            Web3.to_bytes(hexstr=data['executionPayloadRoot']),
        )

    def _update_verify_data(
        self, verify_data: dict, withdrawal_data: dict, pod: ChecksumAddress
    ) -> dict:
        if verify_data.get(pod):
            verify_data[pod]['withdrawal_fields'].append(withdrawal_data['WithdrawalFields'])
            verify_data[pod]['withdrawal_proofs'].append(
                WithdrawalsProcessor._withdrawal_proofs(withdrawal_data)
            )
            verify_data[pod]['validator_fields'].append(
                [Web3.to_bytes(hexstr=x) for x in withdrawal_data['ValidatorFields']]
            )
            verify_data[pod]['validator_fields_proofs'].append(
                b''.join([Web3.to_bytes(hexstr=x) for x in withdrawal_data['ValidatorProof']])
            )
        else:
            verify_data[pod] = {
                'oracle_timestamp': int(withdrawal_data['oracleTimestamp']),
                'state_root_proof': (
                    Web3.to_bytes(hexstr=withdrawal_data['beaconStateRoot']),
                    b''.join(
                        [
                            Web3.to_bytes(hexstr=x)
                            for x in withdrawal_data['StateRootAgainstLatestBlockHeaderProof']
                        ]
                    ),
                ),
                'withdrawal_fields': [withdrawal_data['WithdrawalFields']],
                'withdrawal_proofs': [WithdrawalsProcessor._withdrawal_proofs(withdrawal_data)],
                'validator_fields': [
                    [Web3.to_bytes(hexstr=x) for x in withdrawal_data['ValidatorFields']]
                ],
                'validator_fields_proofs': [
                    b''.join([Web3.to_bytes(hexstr=x) for x in withdrawal_data['ValidatorProof']])
                ],
            }
        return verify_data


class DelayedWithdrawalsProcessor:
    '''
    If there are any delayed withdrawals completed, call
    https://github.com/stakewise/v3-core/blob/main/contracts/
    vaults/ethereum/restake/EigenPodOwner.sol#L189.
    You can fetch claimable delayed withdrawals with
    https://github.com/Layr-Labs/eigenlayer-contracts/blob/
    mainnet-deployment/src/contracts/interfaces/IDelayedWithdrawalRouter.sol#L46
    '''

    def __init__(
        self, pod_to_owner: dict[ChecksumAddress, ChecksumAddress], block_number: BlockNumber
    ):
        self.block_number = block_number
        self.pod_to_owner = pod_to_owner

    async def get_contact_calls(
        self,
    ) -> list[tuple[ChecksumAddress, HexStr]]:
        calls = []

        for pod in self.pod_to_owner.keys():
            delayed_withdrawal_router = await EigenPodContract(pod).get_delayed_withdrawal_router(
                self.block_number
            )
            delayed_withdrawals = await DelayedWithdrawalRouterContract(
                delayed_withdrawal_router
            ).get_claimable_user_delayed_withdrawals(
                pod, block_number=self.block_number
            )  # pod address?

            call = await EigenPodOwnerContract(
                self.pod_to_owner[pod]
            ).get_claim_delayed_withdrawals_call(max_number=len(delayed_withdrawals))
            calls.append(call)

        return calls


class ExitingValidatorsProcessor:
    '''
    For every validator that is in exiting or higher state, we must call
    https://github.com/stakewise/v3-core/blob/main/
    contracts/vaults/ethereum/restake/EigenPodOwner.sol#L135.
    The shares argument must be the sum of effective balances.
    The effective balances should be fetched using
    https://github.com/Layr-Labs/eigenlayer-contracts/blob/
    v0.2.5-mainnet-m2-minor-eigenpod-upgrade/src/contracts/pods/EigenPod.sol#L806
    :return:
    '''

    def __init__(
        self, pod_to_owner: dict[ChecksumAddress, ChecksumAddress], block_number: BlockNumber
    ):
        self.block_number = block_number
        self.pod_to_owner = pod_to_owner

    async def call(
        self,
        vault_validators: list[Validator],
    ) -> None:
        active_validators = [val for val in vault_validators if val.status in ACTIVE_STATUSES]

        validators_per_pod: dict[ChecksumAddress, list[Validator]] = defaultdict(list)
        for validator in active_validators:
            validators_per_pod[validator.withdrawal_address].append(validator)

        for pod, pod_owner in self.pod_to_owner.items():
            pod_shares = await eigenpod_manager_contract.get_pod_shares(
                pod_owner, block_number=self.block_number
            )
            effective_balances = 0
            for validator in validators_per_pod.get(pod, []):
                validator_info = await EigenPodContract(pod).get_validator_pubkey_to_info(
                    validator.public_key, block_number=self.block_number
                )
                effective_balances += validator_info.restaked_balance_gwei

            MIN_DELTA = Web3.to_wei(32, 'ether')
            current_delta = pod_shares - effective_balances
            if current_delta > MIN_DELTA:
                await submit_queue_withdrawal_transaction(self.pod_to_owner[pod], current_delta)


class CompleteWithdrawalsProcessor:
    '''
    Keep track of all the queued withdrawals using WithdrawalQueued event:
    https://github.com/Layr-Labs/eigenlayer-contracts/blob/
    v0.2.5-mainnet-m2-minor-eigenpod-upgrade/src/contracts/interfaces/IDelegationManager.sol#L135.
    Mark withdrawal as undelegation=True if there is StakerUndelegated  or
    StakerForceUndelegated event in the same block as WithdrawalQueued event.
    For every withdrawal:
    Check whether it can be processed by checking that the current block is higher that
    withdrawal.startBlock + withdrawalsDelayBlocks . withdrawalsDelayBlocks  is calculated
    as max(
    minWithdrawalDelayBlocks,
     strategyWithdrawalDelayBlocks[0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0])
    can be fetched in https://github.com/Layr-Labs/eigenlayer-contr
    acts/blob/v0.2.5-mainnet-m2-minor-eigenpod-upgrade/
    src/contracts/core/DelegationManagerStorage.sol#L85 and
    https://github.com/Layr-Labs/eigenlayer-contracts/blob/
     v0.2.5-mainnet-m2-minor-eigenpod-upgrade/src/contracts/interfaces/IDelegationManager.sol#L396
    If the withdrawal is undelegation , set receiveAsTokens=False , otherwise True .
    NB! When receiveAsTokens is True
    the balance of the eigen pod must be >= that withdrawal.shares
    Clean up processed withdrawal
    '''

    def __init__(
        self, pod_to_owner: dict[ChecksumAddress, ChecksumAddress], block_number: BlockNumber
    ):
        self.block_number = block_number
        self.pod_to_owner = pod_to_owner

    # pylint: disable-next=too-many-locals
    async def call(
        self,
    ) -> None:
        from_block = await self._get_from_block()

        queued_withdrawals_events = await delegation_manager_contract.get_withdrawal_queued_events(
            from_block=from_block, to_block=self.block_number
        )

        queued_withdrawals_per_pod = defaultdict(list)
        for withdrawal_event in queued_withdrawals_events:
            if withdrawal_event.withdrawer in self.pod_to_owner.keys():
                queued_withdrawals_per_pod[withdrawal_event.withdrawer].append(withdrawal_event)

        last_block_number = None
        min_withdrawal_delay_blocks = (
            await delegation_manager_contract.get_min_withdrawal_delay_blocks(self.block_number)
        )
        strategy_withdrawal_delay_blocks = (
            await delegation_manager_contract.get_strategy_withdrawal_delay_blocks(
                strategy=EIGENLAYER_DEFAULT_STRATEGY,
                block_number=self.block_number,
            )
        )
        withdrawals_delay_blocks = max(
            min_withdrawal_delay_blocks, strategy_withdrawal_delay_blocks
        )
        staker_undelegated_events = await delegation_manager_contract.get_staker_undelegated_events(
            from_block=from_block,
            to_block=self.block_number,
        )
        staker_force_undelegated_events = (
            await delegation_manager_contract.get_staker_force_undelegated_events(
                from_block=from_block,
                to_block=self.block_number,
            )
        )
        undelegated_blocks = {
            e.blockNumber  # type: ignore[attr-defined]
            for e in [*staker_undelegated_events, *staker_force_undelegated_events]
        }
        for pod, withdrawals in queued_withdrawals_per_pod.items():
            for withdrawal in withdrawals:
                if withdrawal.block_number in undelegated_blocks:
                    withdrawal.undelegation = True

                if self.block_number < withdrawal.start_block + withdrawals_delay_blocks:
                    continue

                receive_as_tokens = True
                if withdrawal.undelegation:
                    receive_as_tokens = False

                if receive_as_tokens:
                    pod_balance = await execution_client.eth.get_balance(pod)
                    if pod_balance < withdrawal.total_shares:
                        logger.info('')
                        continue

                await submit_complete_queued_withdrawal_transaction(
                    self.pod_to_owner[pod],
                    delegated_to=withdrawal.delegated_to,
                    nonce=withdrawal.nonce,
                    shares=withdrawal.shares[0],
                    start_block=withdrawal.start_block,
                    receive_as_tokens=receive_as_tokens,
                )

                if not last_block_number or withdrawal.start_block > last_block_number:
                    last_block_number = withdrawal.start_block

        if last_block_number:
            CheckpointsCrud().update_checkpoint_block_number(
                checkpoint_type=CheckpointType.COMPLETED,
                block_number=last_block_number,
            )

    async def _get_from_block(self):
        last_completed_withdrawals_block = CheckpointsCrud().get_checkpoint_block_number(
            CheckpointType.COMPLETED
        )
        if last_completed_withdrawals_block:
            return last_completed_withdrawals_block
        return settings.network_config.KEEPER_GENESIS_BLOCK


def _proof_to_bytes(value: list[HexStr]) -> bytes:
    return b''.join([Web3.to_bytes(hexstr=x) for x in value])
