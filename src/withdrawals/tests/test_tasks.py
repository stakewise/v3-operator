from unittest import mock

import pytest
from eth_typing import HexStr
from sw_utils import ValidatorStatus
from web3.types import BlockNumber, Gwei, Wei

from src.common.app_state import AppState
from src.common.tests.factories import create_chain_head
from src.common.tests.utils import ether_to_gwei
from src.common.typings import PendingPartialWithdrawal, Singleton
from src.config.networks import HOODI
from src.config.settings import WITHDRAWALS_INTERVAL, settings
from src.validators.database import VaultValidatorCrud
from src.validators.tests.factories import create_consensus_validator
from src.validators.typings import ValidatorConsolidationData
from src.withdrawals.assets import calculate_withdrawal_buffer
from src.withdrawals.tasks import (
    ValidatorWithdrawalSubtask,
    WithdrawalIntervalMixin,
    _fetch_oracle_exiting_validators,
    _filter_exitable_validators,
    _filter_full_withdrawals,
    _filter_non_exiting_validators,
    _get_partial_withdrawals,
    _get_withdrawals,
    _is_pending_partial_withdrawals_queue_full,
)
from src.withdrawals.typings import ExitQueueAssets


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

    # buffer included in queued_assets: need + buffer fits within the largest
    # validator's capacity, so it is requested from that validator alone
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
    need = ether_to_gwei(10)
    buffer = ether_to_gwei(2)
    expected = {'0x2': ether_to_gwei(12)}
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=Gwei(need + buffer),
        validator_partial_withdrawals={},
    )
    assert result == expected

    # buffer included in queued_assets: need + buffer exceeds the largest validator's
    # capacity, so the request is capped there and spills over to the next validator
    need = ether_to_gwei(17)
    buffer = ether_to_gwei(4)
    expected = {'0x2': ether_to_gwei(18), '0x1': ether_to_gwei(3)}
    result = _get_partial_withdrawals(
        partial_validators=validators,
        queued_assets=Gwei(need + buffer),
        validator_partial_withdrawals={},
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=pending_partial_withdrawals,
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=pending_partial_withdrawals,
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes={1},
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
            consolidation_data=ValidatorConsolidationData(is_source=False, is_target=True),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
            pending_balance=ether_to_gwei(1800),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
            pending_balance=ether_to_gwei(5),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
    )
    expected = {}
    assert result == expected
    # handles case with no active validators
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = []

    result = await _get_withdrawals(
        chain_head=chain_head,
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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
            consolidation_data=ValidatorConsolidationData(is_source=True, is_target=False),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
    )
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected


async def test_get_withdrawals_excludes_oracle_exiting_validators_from_partials(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)

    # v1 is oracle-exiting but still ACTIVE_ONGOING on the CL and has the largest
    # balance, so it would be picked first by balance-descending sort. It must be
    # excluded from partial selection entirely, leaving v2 to cover the request.
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(5)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(100),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=90,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes={1},
    )
    expected = {'0x2': ether_to_gwei(5)}
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes={1},
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
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


def test_is_pending_partial_withdrawals_queue_full():
    limit = 100

    with mock.patch.object(settings.network_config, 'PENDING_PARTIAL_WITHDRAWALS_LIMIT', new=limit):
        assert _is_pending_partial_withdrawals_queue_full(limit - 1) is False
        assert _is_pending_partial_withdrawals_queue_full(limit) is True
        assert _is_pending_partial_withdrawals_queue_full(limit + 1) is True


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
    )
    assert len(result) == 1
    assert result[0].index == 1

    # validators_with_consolidations_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2,
            activation_epoch=10,
            status=ValidatorStatus.ACTIVE_ONGOING,
            balance=32,
            consolidation_data=ValidatorConsolidationData(is_source=False, is_target=True),
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes=set(),
    )
    assert len(result) == 1
    assert result[0].index == 1

    # validators_with_consolidation_sources_are_excluded
    validators = [
        create_consensus_validator(
            index=1, activation_epoch=10, status=ValidatorStatus.ACTIVE_ONGOING, balance=32
        ),
        create_consensus_validator(
            index=2,
            activation_epoch=10,
            status=ValidatorStatus.ACTIVE_ONGOING,
            balance=32,
            consolidation_data=ValidatorConsolidationData(is_source=True, is_target=False),
        ),
    ]
    result = _filter_exitable_validators(
        validators,
        max_activation_epoch=12,
        oracle_exit_indexes=set(),
        partial_withdrawal_indexes=set(),
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
            pending_balance=ether_to_gwei(1800),
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
    # a validator that isn't ACTIVE_ONGOING (e.g. already exiting) is dropped
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

    # a validator that isn't ACTIVE_ONGOING (e.g. still pending) is also excluded
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
            buffer=Gwei(0),
            queued_assets=queued_assets,
            consensus_validators=consensus_validators,
            pending_partial_withdrawals=[],
            validator_min_active_epochs=10,
            oracle_exit_indexes=set(),
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
            pending_balance=ether_to_gwei(50),
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
        buffer=Gwei(0),
        queued_assets=queued_assets,
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
    )
    # '0x1' (10+50 effective) exits first but only 10 ETH counts against queued_assets,
    # so '0x2' exits too
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(0)}
    assert result == expected


async def test_get_withdrawals_buffer_does_not_trigger_full_exit(data_dir):
    """A buffer that pushes the buffered request above partial_capacity must not flip
    the partial-only branch into a full exit: the branch decision uses the unbuffered
    shortfall, and `_get_partial_withdrawals` caps the buffered request at capacity.
    """
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    chain_head = create_chain_head(epoch=500)
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
        queued_assets=ether_to_gwei(7.9),  # just below the validator's 8 ETH capacity
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        buffer=ether_to_gwei(1),
    )
    expected = {'0x1': ether_to_gwei(8)}
    assert result == expected


async def test_get_withdrawals_full_exit_covers_shortfall_skips_buffered_partial(data_dir):
    """A full exit that already covers the shortfall on its own must not trigger a
    buffer-only partial top-up on other validators: the shortfall is 0 at that point,
    so requesting `buffer` gwei of partials from '0x2' would be pure overpayment.
    """
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    chain_head = create_chain_head(epoch=500)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(32),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
            is_compounding=False,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(40),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=ether_to_gwei(20),
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        buffer=Gwei(20_000_000),
    )
    expected = {'0x1': Gwei(0)}
    assert result == expected


async def test_get_withdrawals_full_exit_shortfall_tail_still_gets_buffer(data_dir):
    """When the full exit leaves a genuine remaining shortfall, the buffer must still
    be applied to the partial top-up covering that tail.
    """
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    chain_head = create_chain_head(epoch=500)
    consensus_validators = [
        create_consensus_validator(
            public_key='0x1',
            index=1,
            balance=ether_to_gwei(32),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
            is_compounding=False,
        ),
        create_consensus_validator(
            public_key='0x2',
            index=2,
            balance=ether_to_gwei(50),
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=200,
        ),
    ]
    result = await _get_withdrawals(
        chain_head=chain_head,
        queued_assets=ether_to_gwei(40),
        consensus_validators=consensus_validators,
        pending_partial_withdrawals=[],
        validator_min_active_epochs=10,
        oracle_exit_indexes=set(),
        buffer=Gwei(20_000_000),
    )
    expected = {'0x1': Gwei(0), '0x2': Gwei(ether_to_gwei(8) + 20_000_000)}
    assert result == expected


# pylint: disable-next=too-many-locals
async def test_process_submits_shortfall_plus_buffer(data_dir, reset_app_state):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    chain_head = create_chain_head(epoch=500)
    protocol_config = mock.MagicMock(validator_min_active_epochs=10)
    # a single compounding validator with plenty of partial-withdrawal capacity
    validator = create_consensus_validator(
        public_key='0x1',
        index=1,
        balance=ether_to_gwei(40),
        status=ValidatorStatus.ACTIVE_ONGOING,
        activation_epoch=200,
    )
    missing = ether_to_gwei(1)
    total = missing
    avg_reward_per_second = 636_924_636
    rewards_delay = 43_200
    pending_partials_count = 0
    exit_queue = ExitQueueAssets(missing=missing, total=total)
    buffer = calculate_withdrawal_buffer(
        total_queue_assets=total,
        pending_partials_count=pending_partials_count,
        avg_reward_per_second=avg_reward_per_second,
        rewards_delay=rewards_delay,
        network_config=settings.network_config,
    )
    expected_withdrawals = {'0x1': Gwei(missing + buffer)}

    with mock.patch(
        'src.withdrawals.tasks.get_chain_latest_head', return_value=chain_head
    ), mock.patch(
        'src.withdrawals.tasks.get_protocol_config', return_value=protocol_config
    ), mock.patch.object(
        WithdrawalIntervalMixin, '_is_withdrawal_interval_passed', return_value=True
    ), mock.patch.object(
        VaultValidatorCrud, 'get_vault_validators', return_value=[validator]
    ), mock.patch(
        'src.withdrawals.tasks.build_consensus_validators', return_value=[validator]
    ), mock.patch(
        'src.withdrawals.tasks._fetch_oracle_exiting_validators', return_value=[]
    ), mock.patch(
        'src.withdrawals.tasks.get_pending_partial_withdrawals', return_value=[]
    ), mock.patch(
        'src.withdrawals.tasks.get_redemption_assets', return_value=Wei(0)
    ), mock.patch(
        'src.withdrawals.tasks.get_queued_assets', return_value=exit_queue
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count', return_value=pending_partials_count
    ), mock.patch(
        'src.withdrawals.tasks.os_token_vault_controller_contract.avg_reward_per_second',
        return_value=avg_reward_per_second,
    ), mock.patch(
        'src.withdrawals.tasks.keeper_contract.rewards_delay', return_value=rewards_delay
    ), mock.patch(
        'src.withdrawals.tasks.apply_pending_deposits', return_value=([validator], [])
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawal_request_fee', return_value=Wei(0)
    ), mock.patch(
        'src.withdrawals.tasks.submit_withdraw_validators', return_value=HexStr('0xabc')
    ) as mocked_submit, mock.patch(
        'src.withdrawals.tasks.execution_client', new=mock.AsyncMock()
    ) as mocked_execution_client:
        mocked_execution_client.eth.get_transaction.return_value = {'blockNumber': 123}
        subtask = ValidatorWithdrawalSubtask(relayer=None)
        await subtask.process()

    mocked_submit.assert_called_once()
    assert mocked_submit.call_args.kwargs['withdrawals'] == expected_withdrawals


# pylint: disable-next=too-many-locals
async def test_process_submits_tiny_shortfall_without_threshold(data_dir, reset_app_state):
    """There is no minimum-shortfall threshold: even a 10 Gwei shortfall, for which the
    computed buffer rounds down to 0, is still submitted for withdrawal.
    """
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    chain_head = create_chain_head(epoch=500)
    protocol_config = mock.MagicMock(validator_min_active_epochs=10)
    validator = create_consensus_validator(
        public_key='0x1',
        index=1,
        balance=ether_to_gwei(40),
        status=ValidatorStatus.ACTIVE_ONGOING,
        activation_epoch=200,
    )
    missing = Gwei(10)
    exit_queue = ExitQueueAssets(missing=missing, total=missing)

    with mock.patch(
        'src.withdrawals.tasks.get_chain_latest_head', return_value=chain_head
    ), mock.patch(
        'src.withdrawals.tasks.get_protocol_config', return_value=protocol_config
    ), mock.patch.object(
        WithdrawalIntervalMixin, '_is_withdrawal_interval_passed', return_value=True
    ), mock.patch.object(
        VaultValidatorCrud, 'get_vault_validators', return_value=[validator]
    ), mock.patch(
        'src.withdrawals.tasks.build_consensus_validators', return_value=[validator]
    ), mock.patch(
        'src.withdrawals.tasks._fetch_oracle_exiting_validators', return_value=[]
    ), mock.patch(
        'src.withdrawals.tasks.get_pending_partial_withdrawals', return_value=[]
    ), mock.patch(
        'src.withdrawals.tasks.get_redemption_assets', return_value=Wei(0)
    ), mock.patch(
        'src.withdrawals.tasks.get_queued_assets', return_value=exit_queue
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count', return_value=0
    ), mock.patch(
        'src.withdrawals.tasks.os_token_vault_controller_contract.avg_reward_per_second',
        return_value=636_924_636,
    ), mock.patch(
        'src.withdrawals.tasks.keeper_contract.rewards_delay', return_value=43_200
    ), mock.patch(
        'src.withdrawals.tasks.apply_pending_deposits', return_value=([validator], [])
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawal_request_fee', return_value=Wei(0)
    ), mock.patch(
        'src.withdrawals.tasks.submit_withdraw_validators', return_value=HexStr('0xabc')
    ) as mocked_submit, mock.patch(
        'src.withdrawals.tasks.execution_client', new=mock.AsyncMock()
    ) as mocked_execution_client:
        mocked_execution_client.eth.get_transaction.return_value = {'blockNumber': 123}
        subtask = ValidatorWithdrawalSubtask(relayer=None)
        await subtask.process()

    mocked_submit.assert_called_once()
    assert mocked_submit.call_args.kwargs['withdrawals'] == {'0x1': Gwei(10)}


async def test_process_skips_shortfall_below_min_withdrawal_amount_threshold(
    data_dir, reset_app_state
):
    """A shortfall below the configured min-withdrawal-amount-gwei threshold is not
    submitted for withdrawal.
    """
    settings.set(
        vault=None,
        vault_dir=data_dir,
        network=HOODI,
        min_withdrawal_amount_gwei=Gwei(1_000_000),
    )
    chain_head = create_chain_head(epoch=500)
    protocol_config = mock.MagicMock(validator_min_active_epochs=10)
    validator = create_consensus_validator(
        public_key='0x1',
        index=1,
        balance=ether_to_gwei(40),
        status=ValidatorStatus.ACTIVE_ONGOING,
        activation_epoch=200,
    )
    missing = Gwei(999_999)
    exit_queue = ExitQueueAssets(missing=missing, total=missing)

    with mock.patch(
        'src.withdrawals.tasks.get_chain_latest_head', return_value=chain_head
    ), mock.patch(
        'src.withdrawals.tasks.get_protocol_config', return_value=protocol_config
    ), mock.patch.object(
        WithdrawalIntervalMixin, '_is_withdrawal_interval_passed', return_value=True
    ), mock.patch.object(
        VaultValidatorCrud, 'get_vault_validators', return_value=[validator]
    ), mock.patch(
        'src.withdrawals.tasks.build_consensus_validators', return_value=[validator]
    ), mock.patch(
        'src.withdrawals.tasks._fetch_oracle_exiting_validators', return_value=[]
    ), mock.patch(
        'src.withdrawals.tasks.get_pending_partial_withdrawals', return_value=[]
    ), mock.patch(
        'src.withdrawals.tasks.get_redemption_assets', return_value=Wei(0)
    ), mock.patch(
        'src.withdrawals.tasks.get_queued_assets', return_value=exit_queue
    ), mock.patch(
        'src.withdrawals.tasks.submit_withdraw_validators', return_value=HexStr('0xabc')
    ) as mocked_submit:
        subtask = ValidatorWithdrawalSubtask(relayer=None)
        await subtask.process()

    mocked_submit.assert_not_called()


# pylint: disable-next=too-many-locals
async def test_process_submits_shortfall_at_min_withdrawal_amount_threshold(
    data_dir, reset_app_state
):
    """A shortfall at least as large as the configured min-withdrawal-amount-gwei
    threshold is submitted for withdrawal.
    """
    settings.set(
        vault=None,
        vault_dir=data_dir,
        network=HOODI,
        min_withdrawal_amount_gwei=Gwei(1_000_000),
    )
    chain_head = create_chain_head(epoch=500)
    protocol_config = mock.MagicMock(validator_min_active_epochs=10)
    validator = create_consensus_validator(
        public_key='0x1',
        index=1,
        balance=ether_to_gwei(40),
        status=ValidatorStatus.ACTIVE_ONGOING,
        activation_epoch=200,
    )
    missing = Gwei(1_000_000)
    exit_queue = ExitQueueAssets(missing=missing, total=missing)

    with mock.patch(
        'src.withdrawals.tasks.get_chain_latest_head', return_value=chain_head
    ), mock.patch(
        'src.withdrawals.tasks.get_protocol_config', return_value=protocol_config
    ), mock.patch.object(
        WithdrawalIntervalMixin, '_is_withdrawal_interval_passed', return_value=True
    ), mock.patch.object(
        VaultValidatorCrud, 'get_vault_validators', return_value=[validator]
    ), mock.patch(
        'src.withdrawals.tasks.build_consensus_validators', return_value=[validator]
    ), mock.patch(
        'src.withdrawals.tasks._fetch_oracle_exiting_validators', return_value=[]
    ), mock.patch(
        'src.withdrawals.tasks.get_pending_partial_withdrawals', return_value=[]
    ), mock.patch(
        'src.withdrawals.tasks.get_redemption_assets', return_value=Wei(0)
    ), mock.patch(
        'src.withdrawals.tasks.get_queued_assets', return_value=exit_queue
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count', return_value=0
    ), mock.patch(
        'src.withdrawals.tasks.os_token_vault_controller_contract.avg_reward_per_second',
        return_value=636_924_636,
    ), mock.patch(
        'src.withdrawals.tasks.keeper_contract.rewards_delay', return_value=43_200
    ), mock.patch(
        'src.withdrawals.tasks.apply_pending_deposits', return_value=([validator], [])
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawal_request_fee', return_value=Wei(0)
    ), mock.patch(
        'src.withdrawals.tasks.submit_withdraw_validators', return_value=HexStr('0xabc')
    ) as mocked_submit, mock.patch(
        'src.withdrawals.tasks.execution_client', new=mock.AsyncMock()
    ) as mocked_execution_client:
        mocked_execution_client.eth.get_transaction.return_value = {'blockNumber': 123}
        subtask = ValidatorWithdrawalSubtask(relayer=None)
        await subtask.process()

    mocked_submit.assert_called_once()
