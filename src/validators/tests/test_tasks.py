from web3 import Web3

from src.common.tests.factories import create_validator
from src.common.typings import ValidatorType
from src.config.settings import DEPOSIT_AMOUNT_GWEI, PECTRA_DEPOSIT_AMOUNT_GWEI
from src.validators.tasks import _get_topup_data, _get_validators_amount


def test_get_topup_data():
    validator_1 = create_validator(balance=_to_gwei(32), validator_type=ValidatorType.TWO)
    validator_2 = create_validator(balance=_to_gwei(33), validator_type=ValidatorType.TWO)
    create_validator(balance=_to_gwei(35), validator_type=ValidatorType.ONE)

    data = _get_topup_data([validator_1], amount_gwei=_to_gwei(1))
    assert data == {validator_1.public_key: _to_gwei(1)}

    data = _get_topup_data([validator_1], amount_gwei=_to_gwei(100))
    assert data == {validator_1.public_key: _to_gwei(100)}

    data = _get_topup_data([validator_1, validator_2], amount_gwei=_to_gwei(2100))
    assert data == {
        validator_2.public_key: _to_gwei(2015),
        validator_1.public_key: _to_gwei(85),
    }


def test_get_validators_amount():

    assert _get_validators_amount(0, ValidatorType.ONE) == []
    assert _get_validators_amount(0, ValidatorType.TWO) == []

    assert _get_validators_amount(Web3.to_wei(32, 'ether'), ValidatorType.ONE) == [
        DEPOSIT_AMOUNT_GWEI
    ]
    assert _get_validators_amount(Web3.to_wei(32, 'ether'), ValidatorType.TWO) == [
        DEPOSIT_AMOUNT_GWEI
    ]

    assert _get_validators_amount(Web3.to_wei(33, 'ether'), ValidatorType.ONE) == [
        DEPOSIT_AMOUNT_GWEI,
    ]
    assert _get_validators_amount(Web3.to_wei(33, 'ether'), ValidatorType.TWO) == [_to_gwei(33)]

    assert _get_validators_amount(Web3.to_wei(64, 'ether'), ValidatorType.ONE) == [
        DEPOSIT_AMOUNT_GWEI,
        DEPOSIT_AMOUNT_GWEI,
    ]
    assert _get_validators_amount(Web3.to_wei(64, 'ether'), ValidatorType.TWO) == [_to_gwei(64)]

    assert _get_validators_amount(Web3.to_wei(66, 'ether'), ValidatorType.ONE) == [
        DEPOSIT_AMOUNT_GWEI,
        DEPOSIT_AMOUNT_GWEI,
    ]
    assert _get_validators_amount(Web3.to_wei(66, 'ether'), ValidatorType.TWO) == [_to_gwei(66)]

    assert (
        _get_validators_amount(Web3.to_wei(2048, 'ether'), ValidatorType.ONE)
        == [DEPOSIT_AMOUNT_GWEI] * 64
    )
    assert _get_validators_amount(Web3.to_wei(2048, 'ether'), ValidatorType.TWO) == [
        PECTRA_DEPOSIT_AMOUNT_GWEI
    ]

    assert (
        _get_validators_amount(Web3.to_wei(2050, 'ether'), ValidatorType.ONE)
        == [DEPOSIT_AMOUNT_GWEI] * 64
    )
    assert _get_validators_amount(Web3.to_wei(2050, 'ether'), ValidatorType.TWO) == [
        PECTRA_DEPOSIT_AMOUNT_GWEI
    ]

    assert (
        _get_validators_amount(Web3.to_wei(4096, 'ether'), ValidatorType.ONE)
        == [DEPOSIT_AMOUNT_GWEI] * 128
    )
    assert _get_validators_amount(Web3.to_wei(4096, 'ether'), ValidatorType.TWO) == [
        PECTRA_DEPOSIT_AMOUNT_GWEI,
        PECTRA_DEPOSIT_AMOUNT_GWEI,
    ]


def _to_gwei(value):
    return value * 10**9
