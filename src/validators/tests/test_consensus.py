from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

from sw_utils import ValidatorStatus
from sw_utils.tests import faker
from web3.types import Gwei

from src.common.tests.factories import create_chain_head
from src.common.tests.utils import ether_to_gwei
from src.common.typings import PendingConsolidation
from src.validators.consensus import (
    fetch_funding_validators_balances,
    fetch_pending_deposits_amounts,
)
from src.validators.tests.factories import create_consensus_validator
from src.validators.typings import ConsensusValidator, VaultValidator


async def test_fetch_pending_deposits_amounts_empty_public_keys():
    """No pubkeys requested means no beacon call and an empty result."""
    mock_consensus = AsyncMock()

    with patch('src.validators.consensus.consensus_client', mock_consensus):
        result = await fetch_pending_deposits_amounts(public_keys=set(), slot='100')

    assert result == {}
    mock_consensus.get_pending_deposits.assert_not_called()


async def test_fetch_pending_deposits_amounts_sums_multiple_deposits():
    """Multiple pending deposits for the same pubkey are summed."""
    pub_key = faker.validator_public_key()

    mock_consensus = AsyncMock()
    mock_consensus.get_pending_deposits.return_value = [
        {
            'pubkey': pub_key,
            'amount': str(ether_to_gwei(1000)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '90',
        },
        {
            'pubkey': pub_key,
            'amount': str(ether_to_gwei(800)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '95',
        },
    ]

    with patch('src.validators.consensus.consensus_client', mock_consensus):
        result = await fetch_pending_deposits_amounts(public_keys={pub_key}, slot='100')

    assert result == {pub_key: ether_to_gwei(1800)}
    mock_consensus.get_pending_deposits.assert_called_once_with('100')


async def test_fetch_pending_deposits_amounts_filters_by_requested_public_keys():
    """Deposits for pubkeys outside the requested set are ignored."""
    requested_pub_key = faker.validator_public_key()
    other_pub_key = faker.validator_public_key()

    mock_consensus = AsyncMock()
    mock_consensus.get_pending_deposits.return_value = [
        {
            'pubkey': requested_pub_key,
            'amount': str(ether_to_gwei(32)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '90',
        },
        {
            'pubkey': other_pub_key,
            'amount': str(ether_to_gwei(9999)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '91',
        },
    ]

    with patch('src.validators.consensus.consensus_client', mock_consensus):
        result = await fetch_pending_deposits_amounts(public_keys={requested_pub_key}, slot='100')

    assert result == {requested_pub_key: ether_to_gwei(32)}


async def test_fetch_pending_deposits_amounts_counts_regardless_of_credentials_prefix():
    """Unlike funding balances, every pending deposit counts, not only 0x02-prefixed ones."""
    pub_key = faker.validator_public_key()

    mock_consensus = AsyncMock()
    mock_consensus.get_pending_deposits.return_value = [
        {
            'pubkey': pub_key,
            'amount': str(ether_to_gwei(10)),
            'withdrawal_credentials': '0x01' + '00' * 30,
            'slot': '90',
        },
        {
            'pubkey': pub_key,
            'amount': str(ether_to_gwei(20)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '91',
        },
    ]

    with patch('src.validators.consensus.consensus_client', mock_consensus):
        result = await fetch_pending_deposits_amounts(public_keys={pub_key}, slot='100')

    assert result == {pub_key: ether_to_gwei(30)}


async def test_fetch_funding_validators_balances_adds_pending_consolidation_source_balance(
    vault_validator_crud,
):
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


async def test_fetch_funding_validators_balances_excludes_consolidation_source(
    vault_validator_crud,
):
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


async def test_fetch_funding_validators_balances_excludes_target_when_source_balance_unknown(
    vault_validator_crud,
):
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


async def test_fetch_funding_validators_balances_no_consolidations_baseline(
    vault_validator_crud, compounding_creds
):
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
        ),
        patch(
            'src.validators.consensus.fetch_consensus_validators',
            new_callable=AsyncMock,
            return_value=consensus_validators,
        ),
        patch(
            'src.validators.consensus.get_pending_consolidations',
            new_callable=AsyncMock,
            return_value=pending_consolidations or [],
        ),
        patch('src.validators.consensus.consensus_client', mock_consensus),
    ):
        yield
