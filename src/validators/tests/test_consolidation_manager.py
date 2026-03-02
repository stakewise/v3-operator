from unittest.mock import patch

import pytest
from eth_typing import HexStr
from sw_utils import ChainHead
from sw_utils.tests import faker

from src.common.tests.factories import create_chain_head
from src.common.tests.utils import ether_to_gwei
from src.config.settings import settings
from src.validators.consensus import EXITING_STATUSES
from src.validators.consolidation_manager import (
    ConsolidationChecker,
    ConsolidationSelector,
)
from src.validators.exceptions import ConsolidationError
from src.validators.tests.factories import create_consensus_validator
from src.validators.typings import ConsensusValidator, ConsolidationKeys


@pytest.mark.usefixtures('fake_settings')
class TestConsolidationSelector:
    def test_empty_list_when_no_target_validators(self):
        selector = create_manager(
            vault_validators=[],
            consensus_validators=[],
        )
        result = selector.get_target_source()
        assert result == []

    def test_switches_oldest_0x01_to_0x02(self):
        consensus_validators = [
            create_consensus_validator(
                activation_epoch=1,
                is_compounding=False,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        result = selector.get_target_source()
        assert result == [(consensus_validators[0], consensus_validators[0])]

    def test_consolidation_with_single_compounding(self):
        consensus_validators = [
            create_consensus_validator(
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        result = selector.get_target_source()
        assert result == [(consensus_validators[1], consensus_validators[0])]

    def test_consolidation_to_smallest_balance(self):
        consensus_validators = [
            create_consensus_validator(
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                activation_epoch=1, is_compounding=True, balance=ether_to_gwei(32.1)
            ),
            create_consensus_validator(
                activation_epoch=1, is_compounding=True, balance=ether_to_gwei(32.3)
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        result = selector.get_target_source()
        assert result == [(consensus_validators[1], consensus_validators[0])]

    def test_consolidation_max_balance(self):
        consensus_validators = [
            create_consensus_validator(
                activation_epoch=1, is_compounding=True, balance=ether_to_gwei(32.0)
            ),
            create_consensus_validator(
                activation_epoch=1, is_compounding=False, balance=ether_to_gwei(32.1)
            ),
            create_consensus_validator(
                activation_epoch=2, is_compounding=False, balance=ether_to_gwei(32.2)
            ),
            create_consensus_validator(
                activation_epoch=3, is_compounding=False, balance=ether_to_gwei(32.3)
            ),
        ]

        with patch.object(settings, 'max_validator_balance_gwei', ether_to_gwei(100)):
            selector = create_manager(
                vault_validators=[v.public_key for v in consensus_validators],
                consensus_validators=consensus_validators,
            )
            result = selector.get_target_source()
            assert result == [
                (consensus_validators[0], consensus_validators[1]),
                (consensus_validators[0], consensus_validators[2]),
            ]

    def test_excludes_consolidating_validators(self):
        consensus_validators = [
            create_consensus_validator(
                index=10,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                index=11,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            consolidating_source_indexes={10, 11},
            consolidating_target_indexes={10, 11},
        )
        result = selector.get_target_source()
        assert result == []

    def test_excludes_pending_partial_withdrawals(self):
        consensus_validators = [
            create_consensus_validator(
                index=10,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                index=11,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            pending_partial_withdrawals_indexes={10, 11},
        )
        result = selector.get_target_source()
        assert result == []

    def test_excludes_specified_public_keys(self):
        consensus_validators = [
            create_consensus_validator(
                index=10,
                activation_epoch=1,
                is_compounding=False,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            exclude_public_keys={consensus_validators[0].public_key},
        )
        result = selector.get_target_source()
        assert result == []

    def test_excludes_exiting_validators(self):
        consensus_validators = [
            create_consensus_validator(
                activation_epoch=1,
                is_compounding=False,
                status=status,
            )
            for status in EXITING_STATUSES
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        result = selector.get_target_source()
        assert result == []

    def test_min_activation_epoch(self):
        epoch = 1000
        consensus_validators = [
            create_consensus_validator(
                index=10,
                activation_epoch=epoch - settings.network_config.SHARD_COMMITTEE_PERIOD + 1,
                is_compounding=False,
            ),
        ]
        selector = create_manager(
            chain_head=create_chain_head(epoch),
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        result = selector.get_target_source()
        assert result == []

    def test_excludes_source_as_target_validator(self):
        """Test that target validator is excluded if it's in consolidating_source_indexes"""
        consensus_validators = [
            create_consensus_validator(
                index=10,
                activation_epoch=1,
                is_compounding=True,
            ),
            create_consensus_validator(
                index=11,
                activation_epoch=1,
                is_compounding=False,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            consolidating_source_indexes={
                10
            },  # index 10 is in source consolidation, so can't be target
            consolidating_target_indexes=set(),
        )
        result = selector.get_target_source()
        # Should switch validator 11 from 0x01 to 0x02 since there are no valid targets
        # but validator 11 is available as source
        assert result == [(consensus_validators[1], consensus_validators[1])]

    def test_excludes_source_validator_in_both_indexes(self):
        """Test that source validator is excluded if it's in either source or target consolidating indexes"""
        consensus_validators = [
            create_consensus_validator(
                index=10,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                index=11,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            consolidating_source_indexes={10},  # index 10 is in source consolidation
            consolidating_target_indexes=set(),
        )
        result = selector.get_target_source()
        # Should be empty because the only potential source (index 10) is excluded
        # since it's in consolidating_source_indexes
        assert result == []

        # Test with target indexes too
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            consolidating_source_indexes=set(),
            consolidating_target_indexes={10},  # index 10 is in target consolidation
        )
        result = selector.get_target_source()
        # Should still be empty because the only potential source (index 10) is excluded
        # since it's in consolidating_target_indexes
        assert result == []

    def test_allows_validator_in_target_indexes_as_target(self):
        """Test that target validator is not excluded if it's in consolidating_target_indexes"""
        consensus_validators = [
            create_consensus_validator(
                index=10,
                activation_epoch=1,
                is_compounding=True,
            ),
            create_consensus_validator(
                index=11,
                activation_epoch=1,
                is_compounding=False,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            consolidating_source_indexes=set(),
            consolidating_target_indexes={10},
        )
        result = selector.get_target_source()
        # Validator 10 can still be target even if already in consolidating_target_indexes,
        # so validator 11 consolidates into validator 10
        assert result == [(consensus_validators[0], consensus_validators[1])]

    def test_excludes_validator_in_target_indexes_as_source(self):
        """Test that source validator is excluded if it's in consolidating_target_indexes"""
        consensus_validators = [
            create_consensus_validator(
                index=10,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                index=11,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            consolidating_source_indexes=set(),
            consolidating_target_indexes={
                10
            },  # index 10 is in target consolidation, so can't be source
        )
        result = selector.get_target_source()
        # Should be empty because the only potential source (index 10) is excluded
        # since it's in consolidating_target_indexes
        assert result == []


@pytest.mark.usefixtures('fake_settings')
class TestConsolidationChecker:
    def test_empty_list_when_empty_vault(self):
        pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[pk],
            target_public_key=pk,
        )
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[],
            consensus_validators=[],
        )
        with pytest.raises(
            ConsolidationError,
            match=f'Validator {pk} is not registered in the vault {settings.vault}.',
        ):
            selector.get_target_source()

    def test_switch_from_0x01_to_0x02(self):
        pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[pk],
            target_public_key=pk,
        )

        consensus_validators = [
            create_consensus_validator(
                public_key=pk,
                activation_epoch=1,
                is_compounding=False,
            ),
        ]
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        result = selector.get_target_source()
        assert result == [(consensus_validators[0], consensus_validators[0])]

    def test_switch_from_0x02_to_0x02(self):
        pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[pk],
            target_public_key=pk,
        )

        consensus_validators = [
            create_consensus_validator(
                public_key=pk,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]

        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        with pytest.raises(
            ConsolidationError, match=f'Target validator {pk} is already a compounding validator.'
        ):
            selector.get_target_source()

    def test_consolidation_with_single_compounding(self):
        source_pk = faker.validator_public_key()
        target_pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[source_pk],
            target_public_key=target_pk,
        )

        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                public_key=target_pk,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        result = selector.get_target_source()
        assert result == [(consensus_validators[1], consensus_validators[0])]

    def test_consolidation_to_smallest_balance(self):
        source_pk_1 = faker.validator_public_key()
        source_pk_2 = faker.validator_public_key()
        target_pk_1 = faker.validator_public_key()
        target_pk_2 = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[source_pk_1, source_pk_2],
            target_public_key=target_pk_1,  # This is the intended target, but checker will validate it
        )

        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk_1,
                activation_epoch=1,
                is_compounding=False,
                balance=ether_to_gwei(32.0),
            ),
            create_consensus_validator(
                public_key=source_pk_2,
                activation_epoch=1,
                is_compounding=False,
                balance=ether_to_gwei(32.0),
            ),
            create_consensus_validator(
                public_key=target_pk_1,
                index=100,
                activation_epoch=1,
                is_compounding=True,
                balance=ether_to_gwei(32.1),
            ),
            create_consensus_validator(
                public_key=target_pk_2,
                index=101,
                activation_epoch=1,
                is_compounding=True,
                balance=ether_to_gwei(32.3),
            ),
        ]
        # Actually, for ConsolidationChecker, it should work with the provided target
        # So the test should expect the consolidation to happen to the specified target_pk_1
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )
        result = selector.get_target_source()
        # ConsolidationChecker validates the specific target provided in consolidation_keys
        assert result == [
            (consensus_validators[2], consensus_validators[0]),
            (consensus_validators[2], consensus_validators[1]),
        ]

    def test_consolidation_max_balance(self):
        source_pk_1 = faker.validator_public_key()
        source_pk_2 = faker.validator_public_key()
        source_pk_3 = faker.validator_public_key()
        target_pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[source_pk_1, source_pk_2, source_pk_3],
            target_public_key=target_pk,
        )

        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk_1,
                activation_epoch=1,
                is_compounding=False,
                balance=ether_to_gwei(32.0),
            ),
            create_consensus_validator(
                public_key=source_pk_2,
                activation_epoch=1,
                is_compounding=False,
                balance=ether_to_gwei(32.1),
            ),
            create_consensus_validator(
                public_key=source_pk_3,
                activation_epoch=1,
                is_compounding=False,
                balance=ether_to_gwei(32.2),
            ),
            create_consensus_validator(
                public_key=target_pk,
                activation_epoch=1,
                is_compounding=True,
                balance=ether_to_gwei(32.0),
            ),
        ]

        with patch.object(settings, 'max_validator_balance_gwei', ether_to_gwei(96.0)):
            selector = create_manager(
                consolidation_keys=consolidation_keys,
                vault_validators=[v.public_key for v in consensus_validators],
                consensus_validators=consensus_validators,
            )

            with pytest.raises(
                ConsolidationError, match='Cannot consolidate validators, total balance exceeds'
            ):
                selector.get_target_source()

    def test_excludes_consolidating_validators(self):
        source_pk = faker.validator_public_key()
        target_pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[source_pk],
            target_public_key=target_pk,
        )

        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk,
                index=10,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                public_key=target_pk,
                index=11,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            consolidating_source_indexes={10},  # Source validator is consolidating
            consolidating_target_indexes=set(),
        )

        with pytest.raises(
            ConsolidationError,
            match=f'Validator {source_pk} is consolidating to another validator.',
        ):
            selector.get_target_source()

        # Also test when target validator is consolidating
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            consolidating_source_indexes={11},  # Target validator is consolidating (as source)
            consolidating_target_indexes=set(),
        )

        with pytest.raises(
            ConsolidationError,
            match=f'Target validator {target_pk} is involved in another consolidation.',
        ):
            selector.get_target_source()

    def test_excludes_pending_partial_withdrawals(self):
        source_pk = faker.validator_public_key()
        target_pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[source_pk],
            target_public_key=target_pk,
        )

        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk,
                index=10,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                public_key=target_pk,
                index=11,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
            pending_partial_withdrawals_indexes={10},  # Source validator has pending withdrawal
        )

        with pytest.raises(
            ConsolidationError,
            match=f'Validator {source_pk} has pending partial withdrawals in the queue.',
        ):
            selector.get_target_source()

    def test_excludes_exiting_validators(self):
        source_pk = faker.validator_public_key()
        target_pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[source_pk],
            target_public_key=target_pk,
        )

        # Test with exiting source validator
        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk,
                activation_epoch=1,
                is_compounding=False,
                status=EXITING_STATUSES[0],
            ),
            create_consensus_validator(
                public_key=target_pk,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )

        with pytest.raises(
            ConsolidationError,
            match=f'Validator {source_pk} is in exiting status {EXITING_STATUSES[0].value}.',
        ):
            selector.get_target_source()

        # Test with exiting target validator
        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                public_key=target_pk,
                activation_epoch=1,
                is_compounding=True,
                status=EXITING_STATUSES[0],
            ),
        ]
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )

        with pytest.raises(
            ConsolidationError,
            match=f'Target validator {target_pk} is in exiting status {EXITING_STATUSES[0].value}.',
        ):
            selector.get_target_source()

    def test_rejects_non_compounding_target(self):
        source_pk = faker.validator_public_key()
        target_pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[source_pk],
            target_public_key=target_pk,
        )

        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk,
                index=10,
                activation_epoch=1,
                is_compounding=False,
            ),
            create_consensus_validator(
                public_key=target_pk,
                index=11,
                activation_epoch=1,
                is_compounding=False,
            ),
        ]
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )

        with pytest.raises(
            ConsolidationError,
            match=f'The target validator {target_pk} is not a compounding validator.',
        ):
            selector.get_target_source()

    def test_min_activation_epoch(self):
        source_pk = faker.validator_public_key()
        target_pk = faker.validator_public_key()
        consolidation_keys = ConsolidationKeys(
            source_public_keys=[source_pk],
            target_public_key=target_pk,
        )

        epoch = 10
        consensus_validators = [
            create_consensus_validator(
                public_key=source_pk,
                index=10,
                activation_epoch=epoch + settings.network_config.SHARD_COMMITTEE_PERIOD - 1,
                is_compounding=False,
            ),
            create_consensus_validator(
                public_key=target_pk,
                index=11,
                activation_epoch=1,
                is_compounding=True,
            ),
        ]
        selector = create_manager(
            consolidation_keys=consolidation_keys,
            chain_head=create_chain_head(epoch),
            vault_validators=[v.public_key for v in consensus_validators],
            consensus_validators=consensus_validators,
        )

        with pytest.raises(
            ConsolidationError,
            match=f'Validator {consensus_validators[0].public_key} is not active enough for consolidation.',
        ):
            selector.get_target_source()


def create_manager(
    consolidation_keys: ConsolidationKeys | None = None,
    chain_head: ChainHead | None = None,
    exclude_public_keys: set[HexStr] | None = None,
    vault_validators: list[HexStr] | None = None,
    consensus_validators: list[ConsensusValidator] | None = None,
    consolidating_source_indexes: set[int] | None = None,
    consolidating_target_indexes: set[int] | None = None,
    pending_partial_withdrawals_indexes: set[int] | None = None,
) -> ConsolidationSelector | ConsolidationChecker:
    self: ConsolidationChecker | ConsolidationSelector
    if chain_head is None:
        chain_head = create_chain_head(epoch=1024)
    if consolidation_keys is not None:
        self = ConsolidationChecker(
            consolidation_keys=consolidation_keys,
            chain_head=chain_head,
        )
    else:
        if exclude_public_keys is None:
            exclude_public_keys = set()
        self = ConsolidationSelector(
            chain_head=chain_head,
            exclude_public_keys=exclude_public_keys,
        )
    self.vault_validators = vault_validators
    self.consensus_validators = consensus_validators

    if consolidating_source_indexes:
        self.consolidating_source_indexes = consolidating_source_indexes
    else:
        self.consolidating_source_indexes = set()

    if consolidating_target_indexes:
        self.consolidating_target_indexes = consolidating_target_indexes
    else:
        self.consolidating_target_indexes = set()

    if pending_partial_withdrawals_indexes:
        self.pending_partial_withdrawals_indexes = pending_partial_withdrawals_indexes
    else:
        self.pending_partial_withdrawals_indexes = set()
    return self
