from unittest import mock

import pytest
from sw_utils import ValidatorStatus

from src.common.tests.factories import create_chain_head
from src.common.tests.utils import ether_to_gwei
from src.config.networks import HOODI
from src.config.settings import settings
from src.validators.tests.factories import create_consensus_validator
from src.withdrawals.tasks import (
    _filter_exitable_validators,
    _get_partial_withdrawals,
    _get_withdrawals,
    _is_pending_partial_withdrawals_queue_full,
)


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
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    withdrawals_amount = ether_to_gwei(8)
    expected = {'0x1': ether_to_gwei(8)}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
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
    result = _get_partial_withdrawals(validators, withdrawals_amount)
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
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    withdrawals_amount = ether_to_gwei(27)
    expected = {'0x3': ether_to_gwei(18), '0x2': ether_to_gwei(8), '0x1': ether_to_gwei(1)}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    validators = []
    withdrawals_amount = 10
    expected = {}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
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
    result = _get_partial_withdrawals(validators, queued_assets)
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
    result = _get_partial_withdrawals(validators, queued_assets)
    assert result == expected


@pytest.mark.asyncio
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(18), '0x3': ether_to_gwei(28)}
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, {1})
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {'0x2': ether_to_gwei(0)}
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
    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {}
    assert result == expected
    # handles case with no active validators
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = []

    result = await _get_withdrawals(chain_head, queued_assets, consensus_validators, 10, set())
    assert result == {}


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


async def test_is_pending_partial_withdrawals_queue_full():
    limit = 100
    with mock.patch.object(
        settings.network_config, 'PENDING_PARTIAL_WITHDRAWALS_LIMIT', new=limit
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count',
        return_value=limit - 1,
    ):
        assert await _is_pending_partial_withdrawals_queue_full() is False

    with mock.patch.object(
        settings.network_config, 'PENDING_PARTIAL_WITHDRAWALS_LIMIT', new=limit
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count',
        return_value=limit,
    ):
        assert await _is_pending_partial_withdrawals_queue_full() is True

    with mock.patch.object(
        settings.network_config, 'PENDING_PARTIAL_WITHDRAWALS_LIMIT', new=limit
    ), mock.patch(
        'src.withdrawals.tasks.get_withdrawals_count',
        return_value=limit + 1,
    ):
        assert await _is_pending_partial_withdrawals_queue_full() is True


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
        validators, max_activation_epoch=12, oracle_exit_indexes=set()
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
        validators, max_activation_epoch=12, oracle_exit_indexes=set()
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
        validators, max_activation_epoch=12, oracle_exit_indexes={2}
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
        validators, max_activation_epoch=12, oracle_exit_indexes=set()
    )
    assert len(result) == 3
    assert result[0].index == 2
    assert result[1].index == 3
    assert result[2].index == 1

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
        validators, max_activation_epoch=12, oracle_exit_indexes={1}
    )
    assert len(result) == 0
