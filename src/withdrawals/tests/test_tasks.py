import pytest
from sw_utils import ValidatorStatus

from src.common.tests.factories import create_chain_head
from src.common.tests.utils import ether_to_gwei
from src.config.networks import HOODI
from src.config.settings import settings
from src.validators.tests.factories import create_consensus_validator
from src.withdrawals.tasks import _get_partial_withdrawals_data, _get_withdrawals_data


def test_get_partial_withdrawals_data():
    validators = {
        '0x1': ether_to_gwei(40),
    }
    withdrawals_amount = ether_to_gwei(8)
    expected = {'0x1': ether_to_gwei(8)}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': ether_to_gwei(33),
        '0x2': ether_to_gwei(45),
        '0x3': ether_to_gwei(55),
        '0x4': ether_to_gwei(43),
    }
    withdrawals_amount = ether_to_gwei(18)
    expected = {'0x3': ether_to_gwei(18)}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': ether_to_gwei(33),
        '0x2': ether_to_gwei(40),
        '0x3': ether_to_gwei(50),
    }

    withdrawals_amount = ether_to_gwei(20)
    expected = {'0x3': ether_to_gwei(18), '0x2': ether_to_gwei(2)}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': ether_to_gwei(33),
        '0x2': ether_to_gwei(40),
        '0x3': ether_to_gwei(50),
    }

    withdrawals_amount = ether_to_gwei(27)
    expected = {'0x3': ether_to_gwei(18), '0x2': ether_to_gwei(8), '0x1': ether_to_gwei(1)}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    validators = {}
    withdrawals_amount = 10
    expected = {}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    # use_single validator withdrawals
    validators = {
        '0x1': ether_to_gwei(40),
        '0x2': ether_to_gwei(50),
    }
    queued_assets = ether_to_gwei(18)
    expected = {
        '0x2': ether_to_gwei(18),
    }
    result = _get_partial_withdrawals_data(validators, queued_assets)
    assert result == expected

    # no_validators_have_sufficient_balance(
    validators = {'0x1': ether_to_gwei(30)}
    queued_assets = ether_to_gwei(40)
    expected = {}
    result = _get_partial_withdrawals_data(validators, queued_assets)
    assert result == expected


@pytest.mark.asyncio
async def test_get_withdrawals_data(data_dir):
    settings.set(vaults=[], data_dir=data_dir, network=HOODI)

    # returns_correct_partial_withdrawals_when_capacity_is_sufficient
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
    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {'0x1': ether_to_gwei(2), '0x2': ether_to_gwei(18)}
    assert result == expected

    # full_withdrawals_when_partial_withdrawals_capacity_is_insufficient
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
    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(0)}

    assert result == expected

    # empty_when_partial_withdrawals_capacity_is_insufficient_and_full_withdrawals_disabled
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
    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, set())
    assert result == {}
    settings.disable_full_withdrawals = False

    # prioritizes_full_withdrawals_when_partial_withdrawals_capacity_is_insufficient
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(90)
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
            status=ValidatorStatus.ACTIVE_EXITING,
            activation_epoch=80,
        ),
    ]
    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(0)}
    assert result == expected

    # no_partial_withdrawals_after_full_withdrawals
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
    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {'0x1': ether_to_gwei(0)}
    assert result == expected

    # full_withdrawals_when_partial_withdrawals_capacity
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
    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {'0x1': ether_to_gwei(0), '0x2': ether_to_gwei(10)}
    assert result == expected

    # skip_partial_withdrawals_from_non_compound_validators
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
    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, set())
    expected = {'0x1': 0}
    assert result == expected

    # excludes_oracle_exit_indexes_from_full_withdrawals
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
    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, {1})
    expected = {'0x2': ether_to_gwei(0)}
    assert result == expected

    # handles_case_with_no_active_validators
    chain_head = create_chain_head(epoch=500)
    queued_assets = ether_to_gwei(20)
    consensus_validators = []

    result = await _get_withdrawals_data(chain_head, queued_assets, consensus_validators, 10, set())
    assert result == {}
