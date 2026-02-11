import logging

from eth_typing import HexStr
from sw_utils import ChainHead

from src.common.consolidations import get_pending_consolidations
from src.common.contracts import VaultContract
from src.common.withdrawals import get_pending_partial_withdrawals
from src.config.settings import settings
from src.validators.consensus import EXITING_STATUSES, fetch_consensus_validators
from src.validators.exceptions import ConsolidationError
from src.validators.typings import ConsensusValidator, ConsolidationKeys

logger = logging.getLogger(__name__)


class ConsolidationManager:
    chain_head: ChainHead
    vault_validators: list[HexStr]
    consensus_validators: list[ConsensusValidator]
    consolidating_source_indexes: set[int]
    consolidating_target_indexes: set[int]
    pending_partial_withdrawals_indexes: set[int]
    exclude_public_keys: set[HexStr]

    @classmethod
    async def create(
        cls,
        consolidation_keys: ConsolidationKeys | None,
        chain_head: ChainHead,
        exclude_public_keys: set[HexStr],
    ) -> 'ConsolidationManager':
        self: ConsolidationManager
        if consolidation_keys is not None:
            self = ConsolidationChecker(
                consolidation_keys=consolidation_keys,
                chain_head=chain_head,
            )
        else:
            self = ConsolidationSelector(
                chain_head=chain_head,
                exclude_public_keys=exclude_public_keys,
            )
        logger.info('Fetching vault validators...')
        self.vault_validators = await VaultContract(
            settings.vault
        ).get_registered_validators_public_keys(
            from_block=settings.vault_first_block,
            to_block=self.chain_head.block_number,
        )
        if consolidation_keys is not None:
            self.consensus_validators = await fetch_consensus_validators(
                consolidation_keys.all_public_keys
            )
        else:
            self.consensus_validators = await fetch_consensus_validators(self.vault_validators)

        pending_partial_withdrawals = await get_pending_partial_withdrawals(
            chain_head, self.consensus_validators
        )
        pending_consolidations = await get_pending_consolidations(
            chain_head, self.consensus_validators
        )
        self.consolidating_source_indexes = set()
        self.consolidating_target_indexes = set()
        for cons in pending_consolidations:
            self.consolidating_source_indexes.add(cons.source_index)
            self.consolidating_target_indexes.add(cons.target_index)

        self.pending_partial_withdrawals_indexes = set()
        for withdrawal in pending_partial_withdrawals:
            self.pending_partial_withdrawals_indexes.add(withdrawal.validator_index)
        return self

    def get_target_source(self) -> list[tuple[ConsensusValidator, ConsensusValidator]]:
        """
        # Source validators must be:
        - unique
        - in the vault
        - not exiting
        - active for at least SHARD_COMMITTEE_PERIOD epochs
        - not consolidating to another validator
        - not consolidating from another validator
        - no pending partial withdrawals in the queue
        - total balance not exceeding the max effective balance when consolidated
        # Target validator must be:
        - in the vault
        - not exiting
        - not consolidating to another validator
        - a compounding validator

        # For switch from 0x01 to 0x02:
        - source and target public keys are the same
        - in the vault
        - not exiting
        - active for at least SHARD_COMMITTEE_PERIOD epochs
        """
        raise NotImplementedError()

    @property
    def max_activation_epoch(self) -> int:
        return self.chain_head.epoch - settings.network_config.SHARD_COMMITTEE_PERIOD


class ConsolidationSelector(ConsolidationManager):
    def __init__(
        self,
        chain_head: ChainHead,
        exclude_public_keys: set[HexStr],
    ):
        self.chain_head = chain_head
        self.exclude_public_keys = exclude_public_keys

    def get_target_source(self) -> list[tuple[ConsensusValidator, ConsensusValidator]]:
        """
        If there are no 0x02 validators,
        take the oldest 0x01 validator and convert it to 0x02.
        If there is a 0x02 validator,
        take the oldest 0x01 validators to top up the target's balance to MAX BALANCE.
        """
        # Candidates on the role of either source or target validator

        (
            source_validators_candidates,
            target_validator_candidates,
        ) = self._find_validators_candidates()
        if not source_validators_candidates or not target_validator_candidates:
            return []

        source_validators_candidates.sort(key=lambda val: val.activation_epoch)
        target_validator_candidates = [
            val for val in target_validator_candidates if val.is_compounding
        ]
        if not target_validator_candidates:
            # there are no 0x02 validators, switch the oldest 0x01 to 0x02
            return [(source_validators_candidates[0], source_validators_candidates[0])]

        # there is at least one 0x02 validator, top up the one with smallest balance
        target_validator = min(target_validator_candidates, key=lambda val: val.balance)

        selected_source_validators: list[ConsensusValidator] = []
        target_balance = target_validator.balance

        for val in source_validators_candidates:
            if target_balance + val.balance > settings.max_validator_balance_gwei:
                break
            selected_source_validators.append(val)
            target_balance += val.balance  # type: ignore

        if selected_source_validators:
            return [(target_validator, val) for val in selected_source_validators]

        # Target validator is almost full, switch the oldest 0x01 to 0x02
        # Only do this if there are source validators available
        return [(source_validators_candidates[0], source_validators_candidates[0])]

    def _find_validators_candidates(
        self,
    ) -> tuple[list[ConsensusValidator], list[ConsensusValidator]]:
        source_validators: list[ConsensusValidator] = []
        target_validators: list[ConsensusValidator] = []
        for val in self.consensus_validators:
            if val.status in EXITING_STATUSES:
                continue
            # Exclude validators that are sources in ongoing consolidations
            if val.index in self.consolidating_source_indexes:
                continue
            if val.public_key in self.exclude_public_keys:
                continue
            target_validators.append(val)

            # additional filters for source validators
            # Source validator must be non-compounding
            if val.is_compounding:
                continue
            if val.activation_epoch >= self.max_activation_epoch:
                continue
            # Source validator cannot be in any ongoing consolidations (either as source or target)
            if val.index in self.consolidating_target_indexes:
                continue
            if val.index in self.pending_partial_withdrawals_indexes:
                continue
            source_validators.append(val)
        return source_validators, target_validators


class ConsolidationChecker(ConsolidationManager):
    def __init__(
        self,
        consolidation_keys: ConsolidationKeys,
        chain_head: ChainHead,
    ):
        self.consolidation_keys = consolidation_keys
        self.chain_head = chain_head

    def get_target_source(self) -> list[tuple[ConsensusValidator, ConsensusValidator]]:
        """
        Validate that provided public keys can be consolidated
        and return the target and source validators info.
        """
        logger.info('Checking selected validators for consolidation...')
        self._validate_public_keys()

        # Validate the source and target validators are in the vault
        for public_key in self.source_public_keys + [self.target_public_key]:
            if public_key not in self.vault_validators:
                raise ConsolidationError(
                    f'Validator {public_key} is not registered in the vault {settings.vault}.'
                )

        # Validate target public key
        target_validator = self._validate_target_validator()
        if self.is_switch_to_compounding():
            return [(target_validator, target_validator)]

        # Validate source public keys
        pubkey_to_validator = {val.public_key: val for val in self.consensus_validators}
        source_validators: list[ConsensusValidator] = []
        for source_public_key in self.source_public_keys:
            source_validator = pubkey_to_validator.get(source_public_key)
            if not source_validator:
                raise ConsolidationError(
                    f'Validator {source_public_key} not found in the consensus layer.'
                )

            # Validate the source validator status
            if source_validator.status in EXITING_STATUSES:
                raise ConsolidationError(
                    f'Validator {source_public_key} is in exiting '
                    f'status {source_validator.status.value}.'
                )

            # Validate the source validator has been active long enough
            if source_validator.activation_epoch >= self.max_activation_epoch:
                raise ConsolidationError(
                    f'Validator {source_validator.public_key}'
                    f' is not active enough for consolidation. '
                    f'It must be active for at least '
                    f'{settings.network_config.SHARD_COMMITTEE_PERIOD}'
                    f' epochs before consolidation.'
                )

            # Validate the source validator is not consolidating
            if (
                source_validator.index in self.consolidating_source_indexes
                or source_validator.index in self.consolidating_target_indexes
            ):
                raise ConsolidationError(
                    f'Validator {source_validator.public_key} '
                    f'is consolidating to another validator.'
                )

            # Validate the source validator has no pending withdrawals in the queue
            if source_validator.index in self.pending_partial_withdrawals_indexes:
                raise ConsolidationError(
                    f'Validator {source_validator.public_key} '
                    f'has pending partial withdrawals in the queue.'
                )

            source_validators.append(source_validator)

        # Validate the total balance won't exceed the max effective balance
        if (
            sum(val.balance for val in self.consensus_validators)
            > settings.max_validator_balance_gwei
        ):
            raise ConsolidationError(
                'Cannot consolidate validators,'
                f' total balance exceeds {settings.max_validator_balance_gwei} Gwei'
            )

        return [(target_validator, source_validator) for source_validator in source_validators]

    def _validate_public_keys(self) -> None:
        # Validate that source public keys are unique
        if len(self.source_public_keys) != len(set(self.source_public_keys)):
            raise ConsolidationError('Source public keys must be unique.')

        # Reject combining switch from 0x01 to 0x02 with consolidation to another validator
        if len(self.source_public_keys) > 1 and self.target_public_key in self.source_public_keys:
            raise ConsolidationError(
                'Cannot switch from 0x01 to 0x02 and consolidate '
                'to another validator in the same request.'
            )

    def _validate_target_validator(
        self,
    ) -> ConsensusValidator:
        target_validators = [
            val for val in self.consensus_validators if val.public_key == self.target_public_key
        ]
        if not target_validators:
            raise ConsolidationError(
                f'Validator {self.target_public_key} not found in the consensus layer.'
            )
        target_validator = target_validators[0]
        if target_validator.status in EXITING_STATUSES:
            raise ConsolidationError(
                f'Target validator {self.target_public_key} is in exiting '
                f'status {target_validator.status.value}.'
            )
        # Target validator cannot be used as source in ongoing consolidations
        if target_validator.index in self.consolidating_source_indexes:
            raise ConsolidationError(
                f'Target validator {self.target_public_key} is involved in another consolidation.'
            )

        if self.is_switch_to_compounding():
            if target_validator.is_compounding:
                raise ConsolidationError(
                    f'Target validator {self.target_public_key} is already a compounding validator.'
                )
            # switch the 0x01 to 0x02
            if target_validator.activation_epoch >= self.max_activation_epoch:
                raise ConsolidationError(
                    f'Validator {self.target_public_key} is not active enough for consolidation. '
                    f'It must be active for at least '
                    f'{settings.network_config.SHARD_COMMITTEE_PERIOD} epochs before consolidation.'
                )
        else:
            if not target_validator.is_compounding:
                raise ConsolidationError(
                    f'The target validator {self.target_public_key}'
                    f' is not a compounding validator.'
                )
        return target_validator

    def is_switch_to_compounding(self) -> bool:
        return (
            len(self.source_public_keys) == 1
            and self.source_public_keys[0] == self.target_public_key
        )

    @property
    def source_public_keys(self) -> list[HexStr]:
        return self.consolidation_keys.source_public_keys

    @property
    def target_public_key(self) -> HexStr:
        return self.consolidation_keys.target_public_key
