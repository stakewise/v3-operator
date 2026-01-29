import logging

import click
from eth_typing import HexStr
from sw_utils import ChainHead

from src.common.consolidations import get_pending_consolidations
from src.common.contracts import VaultContract
from src.common.withdrawals import get_pending_partial_withdrawals
from src.config.settings import settings
from src.validators.consensus import EXITING_STATUSES, fetch_consensus_validators
from src.validators.typings import ConsensusValidator

logger = logging.getLogger(__name__)


class ConsolidationSelector:
    vault_validators: list[HexStr]
    consensus_validators: list[ConsensusValidator]
    consolidating_indexes: set[int]
    pending_partial_withdrawals_indexes: set[int]
    exclude_public_keys: set[HexStr]

    @classmethod
    async def create(
        cls,
        source_public_keys: list[HexStr] | None,
        target_public_key: HexStr | None,
        chain_head: ChainHead,
        exclude_public_keys: set[HexStr],
    ) -> 'ConsolidationSelector':
        klass: type[ConsolidationSelectorSelector] | type[ConsolidationSelectorChecker]
        if source_public_keys is not None:
            klass = ConsolidationSelectorChecker
        else:
            klass = ConsolidationSelectorSelector
        self = klass(
            source_public_keys=source_public_keys,
            target_public_key=target_public_key,
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
        if source_public_keys is not None and target_public_key is not None:
            self.consensus_validators = await fetch_consensus_validators(
                list(set(source_public_keys + [target_public_key]))
            )
        else:
            self.consensus_validators = await fetch_consensus_validators(self.vault_validators)

        pending_partial_withdrawals = await get_pending_partial_withdrawals(
            chain_head, self.consensus_validators
        )
        pending_consolidations = await get_pending_consolidations(
            chain_head, self.consensus_validators
        )
        self.consolidating_indexes = set()
        for cons in pending_consolidations:
            self.consolidating_indexes.add(cons.source_index)
            self.consolidating_indexes.add(cons.target_index)  # todo

        self.pending_partial_withdrawals_indexes = set()
        for withdrawal in pending_partial_withdrawals:
            self.pending_partial_withdrawals_indexes.add(withdrawal.validator_index)
        return self

    def __init__(
        self,
        source_public_keys: list[HexStr] | None,
        target_public_key: HexStr | None,
        chain_head: ChainHead,
        exclude_public_keys: set[HexStr],
    ):
        self.source_public_keys = source_public_keys
        self.target_public_key = target_public_key
        self.chain_head = chain_head
        self.exclude_public_keys = exclude_public_keys

    async def get_target_source(self) -> list[tuple[ConsensusValidator, ConsensusValidator]]:
        '''
         # Source validators must be:
        - unique
        - in the vault
        - not exiting
        - active for at least SHARD_COMMITTEE_PERIOD epochs
        - not consolidating to another validator
        - not consolidations from another validator
        - have no pending partial withdrawals in the queue
        - total balance that won't exceed the max effective balance when consolidated
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
        '''
        raise NotImplementedError()

    def _validate_target_validator(
        self,
        is_switch: bool | None = None,
    ) -> ConsensusValidator:
        target_validators = [
            val for val in self.consensus_validators if val.public_key == self.target_public_key
        ]
        if not target_validators:
            raise click.ClickException(
                f'Validator {self.target_public_key} not found in the consensus layer.'
            )
        target_validator = target_validators[0]
        if target_validator.status in EXITING_STATUSES:
            raise click.ClickException(
                f'Target validator {self.target_public_key} is in exiting '
                f'status {target_validator.status.value}.'
            )
        if target_validator.index in self.consolidating_indexes:
            raise click.ClickException(
                f'Target validator {self.target_public_key} is consolidating to another validator.'
            )
        if target_validator.public_key in self.exclude_public_keys:
            raise click.ClickException(
                f'Target validator {self.target_public_key} is excluded from consolidation.'
            )

        if is_switch is None:
            is_switch = not target_validator.is_compounding

        if is_switch:
            if target_validator.is_compounding:
                raise click.ClickException(
                    f'Target validator {self.target_public_key} is already a compounding validator.'
                )
            # switch the 0x01 to 0x02
            if target_validator.activation_epoch > self.max_activation_epoch:
                raise click.ClickException(
                    f'Validator {self.target_public_key} is not active enough for consolidation. '
                    f'It must be active for at least '
                    f'{settings.network_config.SHARD_COMMITTEE_PERIOD} epochs before consolidation.'
                )
        return target_validator

    @property
    def max_activation_epoch(self) -> int:
        return self.chain_head.epoch - settings.network_config.SHARD_COMMITTEE_PERIOD


# 2 subclasses
class ConsolidationSelectorSelector(ConsolidationSelector):
    async def get_target_source(self) -> list[tuple[ConsensusValidator, ConsensusValidator]]:
        """
        If there are no 0x02 validators,
        take the oldest 0x01 validator and convert it to 0x02 with confirmation prompt.
        If there is 0x02 validator,
        take the oldest 0x01 validators to top up its balance to 2048 ETH / 64 GNO.
        """
        # Candidates on the role of either source or target validator

        source_validators_candidates, target_validator_candidates = (
            self._find_validators_candidates()
        )
        if not target_validator_candidates:
            return []

        source_validators_candidates.sort(key=lambda val: val.activation_epoch)
        if self.target_public_key:
            target_validator = self._validate_target_validator()
            if not target_validator.is_compounding:
                return [(target_validator, target_validator)]

        else:
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

        if self.target_public_key:
            raise click.ClickException(
                'Target validator has insufficient capacity to consolidate any source validators.'
            )

        # Target validator is almost full, switch the oldest 0x01 to 0x02
        return [(selected_source_validators[0], selected_source_validators[0])]

    def _find_validators_candidates(
        self,
    ) -> tuple[list[ConsensusValidator], list[ConsensusValidator]]:
        source_validators: list[ConsensusValidator] = []
        target_validators: list[ConsensusValidator] = []
        for val in self.consensus_validators:
            if val.status in EXITING_STATUSES:
                continue
            if val.index in self.consolidating_indexes:
                continue
            if val.public_key in self.exclude_public_keys:
                continue
            target_validators.append(val)

            # source
            if val.is_compounding:
                continue
            if val.activation_epoch >= self.max_activation_epoch:
                continue
            if val.index in self.pending_partial_withdrawals_indexes:
                continue
            source_validators.append(val)
        return source_validators, target_validators


class ConsolidationSelectorChecker(ConsolidationSelector):
    async def get_target_source(self) -> list[tuple[ConsensusValidator, ConsensusValidator]]:
        """
        Validate that provided public keys can be consolidated
        and returns the target and source validators info.

        """
        if self.source_public_keys is None or self.target_public_key is None:
            raise click.ClickException(
                'Both source_public_keys and target_public_key must be provided for checking.'
            )

        logger.info('Checking selected validators for consolidation...')

        # Validate that source public keys are unique
        if len(self.source_public_keys) != len(set(self.source_public_keys)):
            raise click.ClickException('Source public keys must be unique.')

        # Validate the switch from 0x01 to 0x02 and consolidation to another validator
        if len(self.source_public_keys) > 1 and self.target_public_key in self.source_public_keys:
            raise click.ClickException(
                'Cannot switch from 0x01 to 0x02 and consolidate '
                'to another validator in the same request.'
            )

        # Validate the source and target validators are in the vault
        for public_keys in self.source_public_keys + [self.target_public_key]:
            if public_keys not in self.vault_validators:
                raise click.ClickException(
                    f'Validator {public_keys} is not registered in the vault {settings.vault}.'
                )

        # Validate target public key
        is_switch = is_switch_to_compounding(self.source_public_keys, self.target_public_key)
        target_validator = self._validate_target_validator(is_switch=is_switch)
        if is_switch:
            return [(target_validator, target_validator)]

        # Validate source public keys
        pubkey_to_validator = {val.public_key: val for val in self.consensus_validators}
        source_validators: list[ConsensusValidator] = []
        for source_public_key in self.source_public_keys:
            source_validator = pubkey_to_validator.get(source_public_key)
            if not source_validator:
                raise click.ClickException(
                    f'Validator {source_public_key} not found in the consensus layer.'
                )

            # Validate the source validator status
            if source_validator.status in EXITING_STATUSES:
                raise click.ClickException(
                    f'Validator {source_public_key} is in exiting '
                    f'status {source_validator.status.value}.'
                )

            # Validate the source has been active long enough
            if source_validator.activation_epoch > self.max_activation_epoch:
                raise click.ClickException(
                    f'Validator {source_validator.public_key}'
                    f' is not active enough for consolidation. '
                    f'It must be active for at least '
                    f'{settings.network_config.SHARD_COMMITTEE_PERIOD}'
                    f' epochs before consolidation.'
                )

            # Validate the source validator is not consolidating
            if source_validator.index in self.consolidating_indexes:
                raise click.ClickException(
                    f'Validator {source_validator.public_key} '
                    f'is consolidating to another validator.'
                )
            source_validators.append(source_validator)

            # Validate the source validators has no pending withdrawals in the queue
            if source_validator.index in self.pending_partial_withdrawals_indexes:
                raise click.ClickException(
                    f'Validator {source_validator.public_key} '
                    f'have pending partial withdrawals in the queue. '
                )

        # Validate the total balance won't exceed the max effective balance
        if (
            sum(val.balance for val in self.consensus_validators)
            > settings.max_validator_balance_gwei
        ):
            raise click.ClickException(
                'Cannot consolidate validators,'
                f' total balance exceed {settings.max_validator_balance_gwei} Gwei'
            )

        return [(target_validator, source_validator) for source_validator in source_validators]


def is_switch_to_compounding(source_public_keys: list[HexStr], target_public_key: HexStr) -> bool:
    return len(source_public_keys) == 1 and source_public_keys[0] == target_public_key
