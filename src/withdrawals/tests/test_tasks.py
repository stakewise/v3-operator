import pytest
from sw_utils import ValidatorStatus

from src.common.tests.factories import create_chain_head
from src.common.tests.utils import ether_to_gwei
from src.config.networks import HOODI
from src.config.settings import settings
from src.validators.tests.factories import create_consensus_validator
from src.withdrawals.tasks import (
    _get_partial_withdrawals,
    _get_withdrawals,
    _is_partial_withdrawable_validator,
)


def test_get_partial_withdrawals():
    validators = {
        '0x1': ether_to_gwei(40),
    }
    withdrawals_amount = ether_to_gwei(0)
    expected = {}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': ether_to_gwei(40),
    }
    withdrawals_amount = ether_to_gwei(8)
    expected = {'0x1': ether_to_gwei(8)}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': ether_to_gwei(33),
        '0x2': ether_to_gwei(45),
        '0x3': ether_to_gwei(55),
        '0x4': ether_to_gwei(43),
    }
    withdrawals_amount = ether_to_gwei(18)
    expected = {'0x3': ether_to_gwei(18)}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': ether_to_gwei(33),
        '0x2': ether_to_gwei(40),
        '0x3': ether_to_gwei(50),
    }

    withdrawals_amount = ether_to_gwei(20)
    expected = {'0x3': ether_to_gwei(18), '0x2': ether_to_gwei(2)}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': ether_to_gwei(33),
        '0x2': ether_to_gwei(40),
        '0x3': ether_to_gwei(50),
    }

    withdrawals_amount = ether_to_gwei(27)
    expected = {'0x3': ether_to_gwei(18), '0x2': ether_to_gwei(8), '0x1': ether_to_gwei(1)}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    validators = {}
    withdrawals_amount = 10
    expected = {}
    result = _get_partial_withdrawals(validators, withdrawals_amount)
    assert result == expected

    # use single validator withdrawals
    validators = {
        '0x1': ether_to_gwei(40),
        '0x2': ether_to_gwei(50),
    }
    queued_assets = ether_to_gwei(18)
    expected = {
        '0x2': ether_to_gwei(18),
    }
    result = _get_partial_withdrawals(validators, queued_assets)
    assert result == expected

    # no validators have sufficient balance
    validators = {'0x1': ether_to_gwei(30)}
    queued_assets = ether_to_gwei(40)
    expected = {}
    result = _get_partial_withdrawals(validators, queued_assets)
    assert result == expected


@pytest.mark.asyncio
async def test_get_withdrawals(data_dir):
    settings.set(vaults=[], data_dir=data_dir, network=HOODI)

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

    # full withdrawals when partial withdrawals capacity iz zero
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
    result = _is_partial_withdrawable_validator(validator, epoch)
    assert result is False

    # validator status is not active
    validator = create_consensus_validator(
        balance=ether_to_gwei(32), status=ValidatorStatus.ACTIVE_EXITING, activation_epoch=10
    )
    result = _is_partial_withdrawable_validator(validator, epoch)
    assert result is False

    # validator not active long enough
    validator = create_consensus_validator(
        balance=ether_to_gwei(32), status=ValidatorStatus.ACTIVE_ONGOING, activation_epoch=400
    )
    result = _is_partial_withdrawable_validator(validator, epoch)
    assert result is False

    validator = create_consensus_validator(
        balance=ether_to_gwei(32), status=ValidatorStatus.ACTIVE_ONGOING, activation_epoch=10
    )
    result = _is_partial_withdrawable_validator(validator, epoch)
    assert result is True
