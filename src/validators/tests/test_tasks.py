from web3 import Web3

from src.common.tests.factories import create_validator
from src.common.typings import ValidatorType
from src.config.settings import MAX_EFFECTIVE_BALANCE_GWEI, MIN_ACTIVATION_BALANCE_GWEI
from src.validators.tasks import _get_funding_amounts, _get_validators_amounts


def test_get_validators_amounts():

    assert _get_validators_amounts(0, ValidatorType.V1) == []
    assert _get_validators_amounts(0, ValidatorType.V2) == []

    assert _get_validators_amounts(Web3.to_wei(32, 'ether'), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]
    assert _get_validators_amounts(Web3.to_wei(32, 'ether'), ValidatorType.V2) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]

    assert _get_validators_amounts(Web3.to_wei(33, 'ether'), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_validators_amounts(Web3.to_wei(33, 'ether'), ValidatorType.V2) == [_to_gwei(33)]

    assert _get_validators_amounts(Web3.to_wei(64, 'ether'), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_validators_amounts(Web3.to_wei(64, 'ether'), ValidatorType.V2) == [_to_gwei(64)]

    assert _get_validators_amounts(Web3.to_wei(66, 'ether'), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_validators_amounts(Web3.to_wei(66, 'ether'), ValidatorType.V2) == [_to_gwei(66)]

    assert (
        _get_validators_amounts(Web3.to_wei(2048, 'ether'), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert _get_validators_amounts(Web3.to_wei(2048, 'ether'), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI
    ]

    assert (
        _get_validators_amounts(Web3.to_wei(2050, 'ether'), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert (
        _get_validators_amounts(Web3.to_wei(2081, 'ether'), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 65
    )
    assert _get_validators_amounts(Web3.to_wei(2050, 'ether'), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI
    ]

    assert _get_validators_amounts(Web3.to_wei(2081, 'ether'), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI,
        _to_gwei(33),
    ]
    assert (
        _get_validators_amounts(Web3.to_wei(4096, 'ether'), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 128
    )
    assert _get_validators_amounts(Web3.to_wei(4096, 'ether'), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI,
        MAX_EFFECTIVE_BALANCE_GWEI,
    ]


def test_get_funding_amounts():
    validator_1 = create_validator(balance=_to_gwei(32), validator_type=ValidatorType.V2)
    validator_2 = create_validator(balance=_to_gwei(33), validator_type=ValidatorType.V2)
    create_validator(balance=_to_gwei(35), validator_type=ValidatorType.V1)

    data = _get_funding_amounts([validator_1], amount=_to_gwei(1))
    assert data == {validator_1.public_key: _to_gwei(1)}

    data = _get_funding_amounts([validator_1], amount=_to_gwei(100))
    assert data == {validator_1.public_key: _to_gwei(100)}

    data = _get_funding_amounts([validator_1, validator_2], amount=_to_gwei(2100))
    assert data == {
        validator_2.public_key: _to_gwei(2015),
        validator_1.public_key: _to_gwei(85),
    }


def _to_gwei(value):
    return value * 10**9
