from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

import pytest
from sw_utils import ValidatorStatus
from sw_utils.tests import faker
from web3.types import Gwei

from src.common.tests.factories import create_chain_head
from src.common.tests.utils import ether_to_gwei, patch_consensus_client
from src.common.typings import PendingConsolidation
from src.validators.consensus import (
    UNKNOWN_VALIDATOR_INDEX,
    build_consensus_validators,
    fetch_funding_validators_balances,
)
from src.validators.tests.factories import create_consensus_validator
from src.validators.typings import (
    ConsensusValidator,
    ValidatorConsolidationData,
    VaultValidator,
)


@pytest.mark.usefixtures('fake_settings')
class TestFetchFundingValidatorsBalances:
    async def test_adds_pending_consolidation_source_balance(self, vault_validator_crud):
        """A pending consolidation's source balance is credited to the target, since that is
        what the target will actually hold once the consolidation is processed."""
        target_balance = ether_to_gwei(40)
        source_balance = ether_to_gwei(20)
        source = create_consensus_validator(
            index=1, balance=source_balance, is_compounding=True, activation_epoch=1
        )
        target = create_consensus_validator(
            index=2, balance=target_balance, is_compounding=True, activation_epoch=1
        )

        vault_validator_crud.save_vault_validators(
            [
                VaultValidator(public_key=source.public_key, block_number=1),
                VaultValidator(public_key=target.public_key, block_number=2),
            ]
        )

        pending_consolidations = [
            PendingConsolidation(source_index=source.index, target_index=target.index)
        ]

        with patch_funding_dependencies(
            consensus_validators=[source, target],
            pending_consolidations=pending_consolidations,
        ):
            result = await fetch_funding_validators_balances()

        assert result == {target.public_key: Gwei(target_balance + source_balance)}

    async def test_excludes_consolidation_source(self, vault_validator_crud):
        """A pending consolidation's source keeps compounding until it is processed, so it
        would otherwise pass the eligibility filter; it must be excluded from the fundable set."""
        source = create_consensus_validator(
            index=1, balance=ether_to_gwei(20), is_compounding=True, activation_epoch=1
        )
        target = create_consensus_validator(
            index=2, balance=ether_to_gwei(40), is_compounding=True, activation_epoch=1
        )

        vault_validator_crud.save_vault_validators(
            [
                VaultValidator(public_key=source.public_key, block_number=1),
                VaultValidator(public_key=target.public_key, block_number=2),
            ]
        )

        pending_consolidations = [
            PendingConsolidation(source_index=source.index, target_index=target.index)
        ]

        with patch_funding_dependencies(
            consensus_validators=[source, target],
            pending_consolidations=pending_consolidations,
        ):
            result = await fetch_funding_validators_balances()

        assert source.public_key not in result

    async def test_excludes_target_when_source_balance_unknown(self, vault_validator_crud):
        """If a pending consolidation's source isn't among the vault's fetched consensus
        validators, its balance can't be determined; the target is dropped from the fundable
        set instead of guessing its post-consolidation balance."""
        target = create_consensus_validator(
            index=2, balance=ether_to_gwei(40), is_compounding=True, activation_epoch=1
        )

        vault_validator_crud.save_vault_validators(
            [VaultValidator(public_key=target.public_key, block_number=1)]
        )

        # source_index has no matching validator in the fetched set
        pending_consolidations = [PendingConsolidation(source_index=999, target_index=target.index)]

        with patch_funding_dependencies(
            consensus_validators=[target],
            pending_consolidations=pending_consolidations,
        ):
            result = await fetch_funding_validators_balances()

        assert result == {}

    async def test_no_consolidations_baseline(self, vault_validator_crud, compounding_creds):
        """Baseline behavior is unchanged when there are no pending consolidations: pending
        deposits are added to balances, and exiting/non-compounding validators are excluded."""
        active = create_consensus_validator(
            index=1,
            balance=ether_to_gwei(40),
            is_compounding=True,
            activation_epoch=1,
            status=ValidatorStatus.ACTIVE_ONGOING,
        )
        exiting = create_consensus_validator(
            index=2,
            balance=ether_to_gwei(50),
            is_compounding=True,
            activation_epoch=1,
            status=ValidatorStatus.ACTIVE_EXITING,
        )
        non_compounding = create_consensus_validator(
            index=3, balance=ether_to_gwei(32), is_compounding=False, activation_epoch=1
        )

        vault_validator_crud.save_vault_validators(
            [
                VaultValidator(public_key=active.public_key, block_number=1),
                VaultValidator(public_key=exiting.public_key, block_number=2),
                VaultValidator(public_key=non_compounding.public_key, block_number=3),
            ]
        )

        pending_deposit_amount = ether_to_gwei(5)
        pending_deposits = [
            {
                'pubkey': active.public_key,
                'amount': str(pending_deposit_amount),
                'withdrawal_credentials': compounding_creds,
            },
        ]

        with patch_funding_dependencies(
            consensus_validators=[active, exiting, non_compounding],
            pending_deposits=pending_deposits,
        ):
            result = await fetch_funding_validators_balances()

        assert result == {active.public_key: Gwei(ether_to_gwei(40) + pending_deposit_amount)}


@pytest.mark.usefixtures('fake_settings')
class TestBuildConsensusValidators:
    async def test_without_flags_leaves_optional_fields_unset(self):
        """The optional fields stay unset when the data behind them was not requested."""
        validator = create_consensus_validator(index=1, with_consolidation_data=False)

        with patch_funding_dependencies(consensus_validators=[validator]):
            result = await build_consensus_validators([validator.public_key])

        assert len(result) == 1
        assert result[0].pending_balance is None
        assert result[0].consolidation_data is None

    async def test_without_flags_skips_extra_lookups(self):
        """Pending deposits and consolidations are not fetched unless explicitly requested."""
        validator = create_consensus_validator(index=1)

        with patch_funding_dependencies(consensus_validators=[validator]) as mocks:
            await build_consensus_validators([validator.public_key])

        mocks['consolidations'].assert_not_called()
        mocks['consensus'].get_pending_deposits.assert_not_called()

    async def test_marks_consolidation_source_and_target(self):
        """Consolidation flags are set and the source balance is credited to the target."""
        source = create_consensus_validator(index=1, balance=ether_to_gwei(20))
        target = create_consensus_validator(index=2, balance=ether_to_gwei(40))
        consolidations = [
            PendingConsolidation(source_index=source.index, target_index=target.index)
        ]

        with patch_funding_dependencies(
            consensus_validators=[source, target], pending_consolidations=consolidations
        ):
            result = await build_consensus_validators(
                [source.public_key, target.public_key], with_consolidations=True
            )

        # the original validators are left untouched
        assert source.consolidation_data == ValidatorConsolidationData(
            is_source=False, is_target=False
        )
        assert target.consolidation_data == ValidatorConsolidationData(
            is_source=False, is_target=False
        )

        result_source, result_target = result
        assert result_source.public_key == source.public_key
        assert result_source.consolidation_data == ValidatorConsolidationData(
            is_source=True, is_target=False, target_balance=None
        )

        assert result_target.public_key == target.public_key
        assert result_target.consolidation_data == ValidatorConsolidationData(
            is_source=False, is_target=True, target_balance=ether_to_gwei(20)
        )

    async def test_leaves_target_balance_unknown_for_missing_source(self):
        """The target's consolidation balance can't be determined when a source is not fetched."""
        target = create_consensus_validator(index=2, balance=ether_to_gwei(40))
        known_source = create_consensus_validator(index=3, balance=ether_to_gwei(10))
        consolidations = [
            PendingConsolidation(source_index=999, target_index=target.index),
            PendingConsolidation(source_index=known_source.index, target_index=target.index),
        ]

        with patch_funding_dependencies(
            consensus_validators=[target, known_source], pending_consolidations=consolidations
        ):
            result = await build_consensus_validators(
                [target.public_key, known_source.public_key], with_consolidations=True
            )

        result_target = result[0]
        assert result_target.public_key == target.public_key
        assert result_target.consolidation_data == ValidatorConsolidationData(
            is_source=False, is_target=True, target_balance=None
        )

    async def test_adds_pending_deposits(self, compounding_creds):
        """Pending deposits fill in pending_balance and add validators absent from the beacon state."""
        validator = create_consensus_validator(index=1, balance=ether_to_gwei(32))
        absent_public_key = faker.validator_public_key()
        pending_deposits = [
            {
                'pubkey': validator.public_key,
                'amount': str(ether_to_gwei(1)),
                'withdrawal_credentials': compounding_creds,
            },
            {
                'pubkey': validator.public_key,
                'amount': str(ether_to_gwei(2)),
                'withdrawal_credentials': compounding_creds,
            },
            {
                'pubkey': absent_public_key,
                'amount': str(ether_to_gwei(32)),
                'withdrawal_credentials': compounding_creds,
            },
        ]

        with patch_funding_dependencies(
            consensus_validators=[validator], pending_deposits=pending_deposits
        ):
            result = await build_consensus_validators(
                [validator.public_key, absent_public_key], with_pending_deposits=True
            )

        # the original validator is left untouched
        assert validator.pending_balance is None

        assert len(result) == 2
        assert result[0].public_key == validator.public_key
        assert result[0].pending_balance == ether_to_gwei(3)

        absent_validator = result[1]
        assert absent_validator.public_key == absent_public_key
        assert absent_validator.index == UNKNOWN_VALIDATOR_INDEX
        assert absent_validator.balance == Gwei(0)
        assert absent_validator.pending_balance == ether_to_gwei(32)
        assert absent_validator.status == ValidatorStatus.PENDING_INITIALIZED
        assert absent_validator.is_compounding is True

    async def test_compounding_deposits_only(self, compounding_creds):
        """Non-0x02 deposits are skipped when only compounding deposits are requested."""
        validator = create_consensus_validator(index=1, balance=ether_to_gwei(32))
        absent_public_key = faker.validator_public_key()
        pending_deposits = [
            {
                'pubkey': validator.public_key,
                'amount': str(ether_to_gwei(1)),
                'withdrawal_credentials': '0x01' + compounding_creds[4:],
            },
            {
                'pubkey': absent_public_key,
                'amount': str(ether_to_gwei(32)),
                'withdrawal_credentials': '0x01' + compounding_creds[4:],
            },
        ]

        with patch_funding_dependencies(
            consensus_validators=[validator], pending_deposits=pending_deposits
        ):
            result = await build_consensus_validators(
                [validator.public_key, absent_public_key],
                with_pending_deposits=True,
                compounding_deposits_only=True,
            )

        assert len(result) == 1
        assert result[0].public_key == validator.public_key
        assert result[0].pending_balance is None

    async def test_empty_public_keys(self):
        """Nothing is fetched at all when no public keys are requested."""
        with patch_funding_dependencies(consensus_validators=[]) as mocks:
            result = await build_consensus_validators(
                [], with_pending_deposits=True, with_consolidations=True
            )

        assert result == []
        mocks['chain_head'].assert_not_called()
        mocks['fetch_validators'].assert_not_called()
        mocks['consolidations'].assert_not_called()
        mocks['consensus'].get_pending_deposits.assert_not_called()

    async def test_uses_given_chain_head(self):
        """A caller-provided chain head is used as the snapshot for every lookup."""
        validator = create_consensus_validator(index=1)
        chain_head = create_chain_head(slot=777)

        with patch_funding_dependencies(consensus_validators=[validator]) as mocks:
            await build_consensus_validators(
                [validator.public_key],
                chain_head=chain_head,
                with_pending_deposits=True,
                with_consolidations=True,
            )

        mocks['chain_head'].assert_not_called()
        assert mocks['fetch_validators'].call_args.kwargs['slot'] == '777'
        assert mocks['consolidations'].call_args.args[0] == chain_head
        mocks['consensus'].get_pending_deposits.assert_called_once_with('777')

    async def test_ignores_deposits_for_other_public_keys(self, compounding_creds):
        """Deposits for pubkeys outside the requested set are neither summed nor turned
        into new validators."""
        validator = create_consensus_validator(index=1)
        pending_deposits = [
            {
                'pubkey': faker.validator_public_key(),
                'amount': str(ether_to_gwei(32)),
                'withdrawal_credentials': compounding_creds,
            },
        ]

        with patch_funding_dependencies(
            consensus_validators=[validator], pending_deposits=pending_deposits
        ):
            result = await build_consensus_validators(
                [validator.public_key], with_pending_deposits=True
            )

        assert len(result) == 1
        assert result[0].pending_balance is None

    async def test_sums_absent_validator_deposits(self, compounding_creds):
        """Several deposits for the same absent pubkey produce a single validator whose
        credentials come from the first deposit."""
        absent_public_key = faker.validator_public_key()
        non_compounding_creds = '0x01' + compounding_creds[4:]
        pending_deposits = [
            {
                'pubkey': absent_public_key,
                'amount': str(ether_to_gwei(32)),
                'withdrawal_credentials': non_compounding_creds,
            },
            {
                'pubkey': absent_public_key,
                'amount': str(ether_to_gwei(8)),
                'withdrawal_credentials': compounding_creds,
            },
        ]

        with patch_funding_dependencies(consensus_validators=[], pending_deposits=pending_deposits):
            result = await build_consensus_validators(
                [absent_public_key], with_pending_deposits=True
            )

        assert len(result) == 1
        assert result[0].public_key == absent_public_key
        assert result[0].pending_balance == ether_to_gwei(40)
        assert result[0].withdrawal_credentials == non_compounding_creds
        assert result[0].is_compounding is False

    async def test_combines_consolidations_and_deposits(self, compounding_creds):
        """Consolidation fields survive the pending deposits pass, and vice versa."""
        source = create_consensus_validator(index=1, balance=ether_to_gwei(20))
        target = create_consensus_validator(index=2, balance=ether_to_gwei(40))
        consolidations = [
            PendingConsolidation(source_index=source.index, target_index=target.index)
        ]
        pending_deposits = [
            {
                'pubkey': target.public_key,
                'amount': str(ether_to_gwei(5)),
                'withdrawal_credentials': compounding_creds,
            },
        ]

        with patch_funding_dependencies(
            consensus_validators=[source, target],
            pending_consolidations=consolidations,
            pending_deposits=pending_deposits,
        ):
            result = await build_consensus_validators(
                [source.public_key, target.public_key],
                with_pending_deposits=True,
                with_consolidations=True,
            )

        result_source, result_target = result
        assert result_source.consolidation_data == ValidatorConsolidationData(
            is_source=True, is_target=False, target_balance=None
        )
        assert result_source.pending_balance is None

        assert result_target.consolidation_data == ValidatorConsolidationData(
            is_source=False, is_target=True, target_balance=ether_to_gwei(20)
        )
        assert result_target.pending_balance == ether_to_gwei(5)


@contextmanager
def patch_funding_dependencies(
    consensus_validators: list[ConsensusValidator],
    pending_consolidations: list[PendingConsolidation] | None = None,
    pending_deposits: list[dict] | None = None,
):
    mock_consensus = AsyncMock()
    mock_consensus.get_pending_deposits.return_value = pending_deposits or []
    with (
        patch(
            'src.validators.consensus.get_latest_vault_v2_validator_public_keys',
            new_callable=AsyncMock,
            return_value=set(),
        ),
        patch(
            'src.validators.consensus.get_chain_latest_head',
            new_callable=AsyncMock,
            return_value=create_chain_head(slot=100),
        ) as mock_chain_head,
        patch(
            'src.validators.consensus.fetch_consensus_validators',
            new_callable=AsyncMock,
            return_value=consensus_validators,
        ) as mock_fetch_validators,
        patch(
            'src.validators.consensus.get_pending_consolidations',
            new_callable=AsyncMock,
            return_value=pending_consolidations or [],
        ) as mock_consolidations,
        patch_consensus_client(mock_consensus),
    ):
        yield {
            'chain_head': mock_chain_head,
            'fetch_validators': mock_fetch_validators,
            'consolidations': mock_consolidations,
            'consensus': mock_consensus,
        }
