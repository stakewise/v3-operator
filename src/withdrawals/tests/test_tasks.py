from unittest import mock

import pytest
from sw_utils import ValidatorStatus
from web3.types import BlockNumber

from src.common.app_state import AppState
from src.common.tests.factories import create_chain_head
from src.common.tests.utils import ether_to_gwei
from src.common.typings import PendingPartialWithdrawal, Singleton
from src.config.networks import HOODI
from src.config.settings import WITHDRAWALS_INTERVAL, settings
from src.validators.tests.factories import create_consensus_validator
from src.withdrawals.tasks import (
    WithdrawalIntervalMixin,
    _fetch_oracle_exiting_validators,
    _filter_exitable_validators,
    _filter_full_withdrawals,
    _filter_non_exiting_validators,
    _get_partial_withdrawals,
    _get_withdrawals,
    _is_pending_partial_withdrawals_queue_full,
)


@pytest.fixture
def reset_app_state():
    """Drop the cached AppState singleton so each test starts with a clean state."""
    Singleton._instances.pop(AppState, None)
    yield
    Singleton._instances.pop(AppState, None)


def test_get_partial_withdrawals():
    validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        )
    ]
    withdrawals_amount = ether_to_gwei(0)
    expected = {}
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=withdrawals_amount,
        validator_partial_withdrawals={},
    )
    assert result == expected

    withdrawals_amount = ether_to_gwei(8)
    expected = {'0x1': ether_to_gwei(8)}
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=withdrawals_amount,
        validator_partial_withdrawals={},
    )
    assert result == expected

    validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(33),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(45),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x3',
            balance=ether_to_gwei(55),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x4',
            balance=ether_to_gwei(43),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    withdrawals_amount = ether_to_gwei(18)
    expected = {'0x3': ether_to_gwei(18)}
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=withdrawals_amount,
        validator_partial_withdrawals={},
    )
    assert result == expected

    validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(33),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x3',
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    withdrawals_amount = ether_to_gwei(20)
    expected = {'0x3': ether_to_gwei(18), '0x2': ether_to_gwei(2)}
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=withdrawals_amount,
        validator_partial_withdrawals={},
    )
    assert result == expected

    withdrawals_amount = ether_to_gwei(27)
    expected = {'0x3': ether_to_gwei(18), '0x2': ether_to_gwei(8), '0x1': ether_to_gwei(1)}
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=withdrawals_amount,
        validator_partial_withdrawals={},
    )
    assert result == expected

    validators = []
    withdrawals_amount = 10
    expected = {}
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=withdrawals_amount,
        validator_partial_withdrawals={},
    )
    assert result == expected

    # use single validator withdrawals
    validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    queued_assets = ether_to_gwei(18)
    expected = {
        '0x2': ether_to_gwei(18),
    }
    result = _get_partial_withdrawals(
        partial_validators=validators, queued_assets=queued_assets, validator_partial_withdrawals={}
    )
    assert result == expected

    # with existing partial withdrawals
    validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(45),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    queued_assets = ether_to_gwei(5)
    validator_partial_withdrawals = {2: ether_to_gwei(18)}
    expected = {
        '0x1': ether_to_gwei(5),
    }
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=queued_assets,
        validator_partial_withdrawals=validator_partial_withdrawals,
    )
    assert result == expected

    # with existing partial withdrawals, correct order
    validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(45),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    queued_assets = ether_to_gwei(15)
    validator_partial_withdrawals = {
        1: ether_to_gwei(1),
        2: ether_to_gwei(8),
    }
    expected = {
        '0x1': ether_to_gwei(12),
        '0x2': ether_to_gwei(3),
    }
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=queued_assets,
        validator_partial_withdrawals=validator_partial_withdrawals,
    )
    assert result == expected

    # no validators have sufficient balance
    validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(30),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    queued_assets = ether_to_gwei(40)
    expected = {}
    result = _get_partial_withdrawals(
        partial_validators=validators, queued_assets=queued_assets, validator_partial_withdrawals={}
    )
    assert result == expected


async def test_get_withdrawals(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)

    # correct partial withdrawals when capacity is sufficient
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)

    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(2), '0x2': ether_to_gwei(18)}
    assert result == expected

    # full withdrawals when partial withdrawals capacity is insufficient
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(100)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(0)}

    assert result == expected

    # empty when partial withdrawals capacity is insufficient and full withdrawals disabled
    settings.disable_full_withdrawals = True

    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(100)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert result == {'0x1': ether_to_gwei(8), '0x2': ether_to_gwei(18)}
    settings.disable_full_withdrawals = False

    # no partial withdrawals after full withdrawals
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(30)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(42),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(0)}
    assert result == expected

    # full withdrawals when partial withdrawals capacity
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(50)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(43),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(10)}
    assert result == expected

    # full withdrawals when partial withdrawals capacity #2
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(86)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
        create_consensus_validator(
            public_key='0x3',
            balance=ether_to_gwei(60),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=80,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(18), '0x3': ether_to_gwei(28)}
    assert result == expected

    # skip full for validators with existing partial withdrawals
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(33)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(32),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    pending_partial_withdrawals = [
        PendingPartialWithdrawal(validator_index=1, amount=ether_to_gwei(1))
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=pending_partial_withdrawals,
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected

    # subtract existing partial withdrawals from balances
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(60)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(96),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(46),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    pending_partial_withdrawals = [
        PendingPartialWithdrawal(validator_index=1, amount=ether_to_gwei(15))
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=pending_partial_withdrawals,
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(49), '0x2': ether_to_gwei(11)}
    assert result == expected

    # full withdrawals when partial withdrawals capacity is zero
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(10)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(32),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(32),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(0)}
    assert result == expected

    # withdrawals all funds
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(500)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(100),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(32),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(0)}
    assert result == expected

    # skip partial withdrawals from non compound validators
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(10)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(35),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
            is_compounding=False,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': 0}
    assert result == expected

    # excludes oracle exit indexes from full withdrawals
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(30),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
            index=1,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(31),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
            index=2,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes={1},
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected

    # excludes target consolidation indexes from full withdrawals
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(30),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
            index=1,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(31),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
            index=2,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes={1},
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected

    # excludes exited oracles from full withdrawals
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(30),
            status=ValidatorStatus.ACTIVE_EXITING,
            activation_epoch=90,
            index=1,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(31),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
            index=2,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected

    # skips full withdrawal of a low-balance validator with large pending deposits
    # in favor of a plain validator (mirrors incident: ~32 ETH CL balance masking
    # ~1800 ETH of pending top-ups still in the entry queue)
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(32),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
            index=1,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
            index=2,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={'0x1': ether_to_gwei(1800)},
    )
    # only the plain validator ('0x2') is exited; '0x1' with the huge pending
    # deposit sorts last and is left untouched
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected

    # queued_assets accounting subtracts a validator's real CL balance, not
    # balance + pending deposits: if the pending deposit were wrongly counted
    # as already-recovered assets, exiting '0x1' would look sufficient and
    # '0x2' would never be exited
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(12)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(10),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
            index=1,
        ),
        create_consensus_validator(
            public_key='0x2',
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
            index=2,
            is_compounding=False,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={'0x1': ether_to_gwei(5)},
    )
    # '0x1' sorts first (10 + 5 = 15 ETH effective, versus '0x2' at 50 ETH), but only
    # its real 10 ETH balance is subtracted from queued_assets, leaving 2 ETH still
    # needed and forcing '0x2' to be exited too
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(0)}
    assert result == expected

    # zero queued assets
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(0)

    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {}
    assert result == expected
    # handles case with no active validators
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = []

    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert result == {}


async def test_get_withdrawals_non_compounding_exit_does_not_reduce_partial_capacity(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)

    # v1 is 0x01 and never contributes to partial_capacity, so its full exit must not
    # decrement it either; only v2/v3 (0x02) capacity should be tracked and consumed
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(67)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
            is_compounding=False,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
        ),
        create_consensus_validator(
            public_key='0x3',
            index=3,
            balance=ether_to_gwei(45),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=80,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    # v1 (40 ETH) is the cheapest to exit and is fully exited, leaving 27 ETH still
    # needed. partial_capacity (31 ETH from v2+v3) is untouched by v1's exit, so it
    # covers the remainder via partials, fattest balance first: v2 gets its full
    # 18 ETH capacity, v3 covers the rest (9 ETH) — v3 must not be fully exited.
    expected = {
        '0x1': ether_to_gwei(0),
        '0x2': ether_to_gwei(18),
        '0x3': ether_to_gwei(9),
    }
    assert result == expected


async def test_get_withdrawals_excludes_consolidation_sources(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)

    # v1 is the source of a still-pending consolidation: it is the cheapest to exit
    # (40 ETH) and, being 0x02 compounding, would also inflate partial_capacity. It
    # must be excluded from both selection paths entirely -- neither fully exited nor
    # partially withdrawn -- leaving v2 to cover the request on its own.
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(30)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes={1},
        pending_deposits={},
    )
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected


async def test_get_withdrawals_excludes_oracle_exiting_from_partial_capacity(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)

    # v1 is still ACTIVE_ONGOING on the CL but already oracle-exiting, so it must not
    # inflate partial_capacity or receive a partial withdrawal; only v2 gets exited.
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes={1},
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected


async def test_get_withdrawals_boundary_activation_epoch_prefers_partial_over_full_exit(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)

    # activation epoch exactly at the SHARD_COMMITTEE_PERIOD boundary is CL-eligible for
    # a partial withdrawal, so it must not be routed into the full-exit branch
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(5)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=chain_head.epoch - settings.network_config.SHARD_COMMITTEE_PERIOD,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    expected = {'0x1': ether_to_gwei(5)}
    assert result == expected


def test_is_partial_withdrawable_validator():
    epoch = 500

    validator = create_consensus_validator(
        balance=ether_to_gwei(32),
        status=ValidatorStatus.ACTIVE_ONGOING,
        activation_epoch=10,
        is_compounding=False,
    )
    result = validator.is_partially_withdrawable(epoch)
    assert result is False

    # validator status is not active
    validator = create_consensus_validator(
        balance=ether_to_gwei(32), status=ValidatorStatus.ACTIVE_EXITING, activation_epoch=10
    )
    result = validator.is_partially_withdrawable(epoch)
    assert result is False

    # validator not active long enough
    validator = create_consensus_validator(
        balance=ether_to_gwei(32), status=ValidatorStatus.ACTIVE_ONGOING, activation_epoch=400
    )
    result = validator.is_partially_withdrawable(epoch)
    assert result is False

    validator = create_consensus_validator(
        balance=ether_to_gwei(32), status=ValidatorStatus.ACTIVE_ONGOING, activation_epoch=10
    )
    result = validator.is_partially_withdrawable(epoch)
    assert result is True

    # activation epoch exactly at the SHARD_COMMITTEE_PERIOD boundary is eligible
    validator = create_consensus_validator(
        balance=ether_to_gwei(32),
        status=ValidatorStatus.ACTIVE_ONGOING,
        activation_epoch=epoch - settings.network_config.SHARD_COMMITTEE_PERIOD,
    )
    result = validator.is_partially_withdrawable(epoch)
    assert result is True


async def test_is_pending_partial_withdrawals_queue_full():
    limit = 100
    chain_head = create_chain_head(epoch=500)

    with mock.patch.object(
        settings.network_config, 'PENDING_PARTIAL_WITHDRAWALS_LIMIT', new=limit
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count',
        return_value=limit - 1,
    ):
        assert await _is_pending_partial_withdrawals_queue_full(chain_head) is False

    with mock.patch.object(
        settings.network_config, 'PENDING_PARTIAL_WITHDRAWALS_LIMIT', new=limit
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count',
        return_value=limit,
    ):
        assert await _is_pending_partial_withdrawals_queue_full(chain_head) is True

    with mock.patch.object(
        settings.network_config, 'PENDING_PARTIAL_WITHDRAWALS_LIMIT', new=limit
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count',
        return_value=limit + 1,
    ):
        assert await _is_pending_partial_withdrawals_queue_full(chain_head) is True


def test_filter_exitable_validators():
    # validators_with_activation_epoch_above_limit_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2, activation_epoch=15, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert len(result) == 1
    assert result[0].index == 1

    # validators_with_non_active_status_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2, activation_epoch=10, status=ValidatorStatus.ACTIVE_EXITING, balance=32
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert len(result) == 1
    assert result[0].index == 1

    # validators_in_oracle_exit_indexes_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes={2},
        partial_withdrawal_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert len(result) == 1
    assert result[0].index == 1

    # validators_with_partial_withdrawals_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes={2},
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert len(result) == 1
    assert result[0].index == 1

    # validators_with_consolidations_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes=set(),
        consolidation_target_indexes={2},
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert len(result) == 1
    assert result[0].index == 1

    # validators_with_consolidation_sources_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes={2},
        pending_deposits={},
    )
    assert len(result) == 1
    assert result[0].index == 1

    # validators_are_sorted_by_balance_and_index
    validators = [
        create_consensus_validator(
            index=2, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=30
        ),
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=3, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=30
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert len(result) == 3
    assert result[0].index == 2
    assert result[1].index == 3
    assert result[2].index == 1

    # validators_with_pending_deposits_sort_last_but_are_not_excluded
    validators = [
        create_consensus_validator(
            index=1,
            public_key='0x1',
            activation_epoch=10,
            status=ValidatorStatus.ACTIVE_ONGOING,
            balance=ether_to_gwei(32),
        ),
        create_consensus_validator(
            index=2,
            public_key='0x2',
            activation_epoch=10,
            status=ValidatorStatus.ACTIVE_ONGOING,
            balance=ether_to_gwei(50),
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={'0x1': ether_to_gwei(1800)},
    )
    assert len(result) == 2
    assert result[0].index == 2
    assert result[1].index == 1

    # no_validators_returned_when_all_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=15, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2, activation_epoch=10, status=ValidatorStatus.ACTIVE_EXITING, balance=32
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes={1},
        partial_withdrawal_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={},
    )
    assert len(result) == 0


def test_filter_full_withdrawals():
    withdrawals = {
        '0x1': ether_to_gwei(0),
        '0x2': ether_to_gwei(5),
        '0x3': ether_to_gwei(0),
    }
    assert _filter_full_withdrawals(withdrawals) == ['0x1', '0x3']
    assert _filter_full_withdrawals({}) == []


def test_filter_non_exiting_validators():
    # an exiting validator's index is dropped even though it is in CAN_BE_EXITED_STATUSES
    validators = [
        create_consensus_validator(index=1, status=ValidatorStatus.ACTIVE_ONGOING, balance=32),
        create_consensus_validator(index=2, status=ValidatorStatus.ACTIVE_EXITING, balance=32),
    ]
    result = _filter_non_exiting_validators(validators, oracle_exiting_validators=[])
    assert [v.index for v in result] == [1]

    # a validator still ACTIVE_ONGOING on the CL but already in the oracle's exiting
    # set is excluded too, so its pending partial isn't counted on top of the balance
    # already summed via the oracle-exiting branch
    validators = [
        create_consensus_validator(index=1, status=ValidatorStatus.ACTIVE_ONGOING, balance=32),
        create_consensus_validator(index=2, status=ValidatorStatus.ACTIVE_ONGOING, balance=32),
    ]
    oracle_exiting_validators = [
        create_consensus_validator(index=2, status=ValidatorStatus.ACTIVE_ONGOING, balance=32),
    ]
    result = _filter_non_exiting_validators(validators, oracle_exiting_validators)
    assert [v.index for v in result] == [1]

    # a validator outside CAN_BE_EXITED_STATUSES (e.g. still pending) is also excluded
    validators = [
        create_consensus_validator(index=1, status=ValidatorStatus.PENDING_QUEUED, balance=32),
    ]
    result = _filter_non_exiting_validators(validators, oracle_exiting_validators=[])
    assert result == []


async def test_fetch_oracle_exiting_validators():
    validator_1 = create_consensus_validator(
        public_key='0x1', index=1, status=ValidatorStatus.ACTIVE_ONGOING, balance=ether_to_gwei(32)
    )
    validator_2 = create_consensus_validator(
        public_key='0x2', index=2, status=ValidatorStatus.ACTIVE_ONGOING, balance=ether_to_gwei(32)
    )
    consensus_validators = [validator_1, validator_2]
    protocol_config = mock.MagicMock()

    # index 99 isn't a vault validator; filtered out
    with mock.patch('src.withdrawals.tasks.poll_active_exits', return_value=[2, 99]):
        result = await _fetch_oracle_exiting_validators(consensus_validators, protocol_config)
    assert result == [validator_2]

    with mock.patch('src.withdrawals.tasks.poll_active_exits', return_value=[]):
        result = await _fetch_oracle_exiting_validators(consensus_validators, protocol_config)
    assert result == []


async def test_is_withdrawal_interval_passed_not_reached(data_dir, reset_app_state):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    blocks_interval = WITHDRAWALS_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
    chain_head = create_chain_head(block_number=100_000, epoch=500)

    app_state = AppState()
    app_state.partial_withdrawal_block = BlockNumber(
        chain_head.block_number - blocks_interval + 1000
    )

    mixin = WithdrawalIntervalMixin()
    result = await mixin._is_withdrawal_interval_passed(app_state, chain_head)

    assert result is False


async def test_is_withdrawal_interval_passed_reached(data_dir, reset_app_state):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    blocks_interval = WITHDRAWALS_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
    chain_head = create_chain_head(block_number=100_000, epoch=500)

    app_state = AppState()
    app_state.partial_withdrawal_block = BlockNumber(
        chain_head.block_number - blocks_interval - 1000
    )

    mixin = WithdrawalIntervalMixin()
    result = await mixin._is_withdrawal_interval_passed(app_state, chain_head)

    assert result is True


async def test_is_withdrawal_interval_passed_backfill_no_events(data_dir, reset_app_state):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    blocks_interval = WITHDRAWALS_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
    chain_head = create_chain_head(block_number=100_000, epoch=500)
    from_block = BlockNumber(chain_head.block_number - blocks_interval)

    app_state = AppState()
    assert app_state.partial_withdrawal_block is None

    mixin = WithdrawalIntervalMixin()
    with mock.patch.object(
        WithdrawalIntervalMixin, '_fetch_last_withdrawals_block', return_value=None
    ):
        result = await mixin._is_withdrawal_interval_passed(app_state, chain_head)

    assert result is True
    # falls back to from_block, not None, to avoid repeating the lookup every block
    assert app_state.partial_withdrawal_block == from_block


async def test_is_withdrawal_interval_passed_backfill_from_event(data_dir, reset_app_state):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    blocks_interval = WITHDRAWALS_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
    chain_head = create_chain_head(block_number=100_000, epoch=500)
    backfilled_block = BlockNumber(chain_head.block_number - blocks_interval + 1500)

    app_state = AppState()
    assert app_state.partial_withdrawal_block is None

    mixin = WithdrawalIntervalMixin()
    with mock.patch.object(
        WithdrawalIntervalMixin,
        '_fetch_last_withdrawals_block',
        return_value=backfilled_block,
    ) as mocked_fetch:
        result = await mixin._is_withdrawal_interval_passed(app_state, chain_head)

    mocked_fetch.assert_awaited_once_with(BlockNumber(chain_head.block_number - blocks_interval))
    # back-filled from the event even though the interval has passed again by now
    assert app_state.partial_withdrawal_block == backfilled_block
    assert result is False


async def test_is_withdrawal_interval_passed_at_exact_boundary(data_dir, reset_app_state):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    blocks_interval = WITHDRAWALS_INTERVAL // settings.network_config.SECONDS_PER_BLOCK
    chain_head = create_chain_head(block_number=100_000, epoch=500)

    app_state = AppState()
    app_state.partial_withdrawal_block = BlockNumber(chain_head.block_number - blocks_interval)

    mixin = WithdrawalIntervalMixin()
    result = await mixin._is_withdrawal_interval_passed(app_state, chain_head)

    # _is_withdrawal_interval_passed uses `>=`, so the interval hasn't passed yet at
    # exactly blocks_interval blocks
    assert result is False


@pytest.mark.parametrize(
    ('queued_assets', 'consensus_validators'),
    [
        # top-branch: partial capacity alone is sufficient
        (
            ether_to_gwei(20),
            [
                create_consensus_validator(
                    public_key='0x1',
                    index=1,
                    balance=ether_to_gwei(40),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=200,
                ),
                create_consensus_validator(
                    public_key='0x2',
                    index=2,
                    balance=ether_to_gwei(50),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=200,
                ),
            ],
        ),
        # mid-loop top-up after one full exit
        (
            ether_to_gwei(50),
            [
                create_consensus_validator(
                    public_key='0x1',
                    index=1,
                    balance=ether_to_gwei(40),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=90,
                ),
                create_consensus_validator(
                    public_key='0x2',
                    index=2,
                    balance=ether_to_gwei(43),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=85,
                ),
            ],
        ),
        # mid-loop top-up spans two validators
        (
            ether_to_gwei(86),
            [
                create_consensus_validator(
                    public_key='0x1',
                    index=1,
                    balance=ether_to_gwei(40),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=90,
                ),
                create_consensus_validator(
                    public_key='0x2',
                    index=2,
                    balance=ether_to_gwei(50),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=85,
                ),
                create_consensus_validator(
                    public_key='0x3',
                    index=3,
                    balance=ether_to_gwei(60),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=80,
                ),
            ],
        ),
        # capacity never catches up with queued_assets
        (
            ether_to_gwei(100),
            [
                create_consensus_validator(
                    public_key='0x1',
                    index=1,
                    balance=ether_to_gwei(40),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=90,
                ),
                create_consensus_validator(
                    public_key='0x2',
                    index=2,
                    balance=ether_to_gwei(50),
                    status=ValidatorStatus.ACTIVE_ONGOING,
                    activation_epoch=85,
                ),
            ],
        ),
    ],
    ids=['partials-only', 'single-topup', 'two-validator-topup', 'gate-never-fires'],
)
async def test_get_withdrawals_partial_topup_called_at_most_once(
    data_dir, queued_assets, consensus_validators
):
    """`_get_partial_withdrawals` runs at most once per `_get_withdrawals` call, and a
    mid-loop call always fully saturates `queued_assets` since `partial_capacity` only
    ever underestimates real capacity at that point.
    """
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    settings.disable_full_withdrawals = False
    chain_head = create_chain_head(epoch=500)

    calls: list[tuple[dict, dict]] = []

    def _spy(**kwargs):
        result = _get_partial_withdrawals(**kwargs)
        calls.append((kwargs, result))
        return result

    with mock.patch('src.withdrawals.tasks._get_partial_withdrawals', side_effect=_spy):
        await _get_withdrawals(
            chain_head=chain_head,
            queued_assets=queued_assets,
            consensus_validators=consensus_validators,
            pending_partial_withdrawals=[],
            validator_min_active_epochs=10,
            oracle_exit_indexes=set(),
            consolidation_target_indexes=set(),
            consolidation_source_indexes=set(),
            pending_deposits={},
        )

    assert len(calls) <= 1
    if calls:
        call_kwargs, call_result = calls[0]
        requested = call_kwargs['queued_assets']
        covered = sum(call_result.values())
        assert requested == 0 or covered == requested


async def test_get_withdrawals_pending_deposit_asymmetry(data_dir):
    """`_filter_exitable_validators`'s sort key credits pending deposits, but
    `_get_withdrawals`'s `queued_assets` subtraction only ever uses real CL balance --
    deposits are never credited even once landed. Validators are 0x01 so
    `partial_capacity` is not a factor.
    """
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    settings.disable_full_withdrawals = False
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(12)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(10),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
            is_compounding=False,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(70),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=85,
            is_compounding=False,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        consolidation_target_indexes=set(),
        consolidation_source_indexes=set(),
        pending_deposits={'0x1': ether_to_gwei(50)},
    )
    # '0x1' (10+50 effective) exits first but only 10 ETH counts against queued_assets,
    # so '0x2' exits too
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(0)}
    assert result == expected
