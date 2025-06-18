from web3 import Web3

from src.common.typings import ValidatorType
from src.config.settings import MAX_EFFECTIVE_BALANCE_GWEI, MIN_ACTIVATION_BALANCE_GWEI
from src.validators.tasks import _get_validators_amount


def test_get_validators_amount():

    assert _get_validators_amount(0, ValidatorType.ONE) == []
    assert _get_validators_amount(0, ValidatorType.TWO) == []

    assert _get_validators_amount(Web3.to_wei(32, 'ether'), ValidatorType.ONE) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]
    assert _get_validators_amount(Web3.to_wei(32, 'ether'), ValidatorType.TWO) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]

    assert _get_validators_amount(Web3.to_wei(33, 'ether'), ValidatorType.ONE) == [
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_validators_amount(Web3.to_wei(33, 'ether'), ValidatorType.TWO) == [_to_gwei(33)]

    assert _get_validators_amount(Web3.to_wei(64, 'ether'), ValidatorType.ONE) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_validators_amount(Web3.to_wei(64, 'ether'), ValidatorType.TWO) == [_to_gwei(64)]

    assert _get_validators_amount(Web3.to_wei(66, 'ether'), ValidatorType.ONE) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_validators_amount(Web3.to_wei(66, 'ether'), ValidatorType.TWO) == [_to_gwei(66)]

    assert (
        _get_validators_amount(Web3.to_wei(2048, 'ether'), ValidatorType.ONE)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert _get_validators_amount(Web3.to_wei(2048, 'ether'), ValidatorType.TWO) == [
        MAX_EFFECTIVE_BALANCE_GWEI
    ]

    assert (
        _get_validators_amount(Web3.to_wei(2050, 'ether'), ValidatorType.ONE)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert _get_validators_amount(Web3.to_wei(2050, 'ether'), ValidatorType.TWO) == [
        MAX_EFFECTIVE_BALANCE_GWEI
    ]

    assert (
        _get_validators_amount(Web3.to_wei(4096, 'ether'), ValidatorType.ONE)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 128
    )
    assert _get_validators_amount(Web3.to_wei(4096, 'ether'), ValidatorType.TWO) == [
        MAX_EFFECTIVE_BALANCE_GWEI,
        MAX_EFFECTIVE_BALANCE_GWEI,
    ]


def _to_gwei(value):
    return value * 10**9
