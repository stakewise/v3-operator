from web3 import Web3

from src.common.tests.factories import create_validator
from src.common.typings import ValidatorType
from src.validators.tasks import _get_topup_data, _get_validators_count


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


def test_get_validators_count():

    assert _get_validators_count(0, ValidatorType.ONE) == 0
    assert _get_validators_count(0, ValidatorType.TWO) == 0

    assert _get_validators_count(Web3.to_wei(32, 'ether'), ValidatorType.ONE) == 1
    assert _get_validators_count(Web3.to_wei(32, 'ether'), ValidatorType.TWO) == 1

    assert _get_validators_count(Web3.to_wei(33, 'ether'), ValidatorType.ONE) == 1
    assert _get_validators_count(Web3.to_wei(32, 'ether'), ValidatorType.TWO) == 1

    assert _get_validators_count(Web3.to_wei(64, 'ether'), ValidatorType.ONE) == 2
    assert _get_validators_count(Web3.to_wei(64, 'ether'), ValidatorType.TWO) == 1

    assert _get_validators_count(Web3.to_wei(64, 'ether'), ValidatorType.ONE) == 2
    assert _get_validators_count(Web3.to_wei(64, 'ether'), ValidatorType.TWO) == 1

    assert _get_validators_count(Web3.to_wei(2048, 'ether'), ValidatorType.ONE) == 64
    assert _get_validators_count(Web3.to_wei(2048, 'ether'), ValidatorType.TWO) == 1

    assert _get_validators_count(Web3.to_wei(2050, 'ether'), ValidatorType.ONE) == 64
    assert _get_validators_count(Web3.to_wei(2050, 'ether'), ValidatorType.TWO) == 1

    assert _get_validators_count(Web3.to_wei(4096, 'ether'), ValidatorType.ONE) == 128
    assert _get_validators_count(Web3.to_wei(4096, 'ether'), ValidatorType.TWO) == 2


def _to_gwei(value):
    return value * 10**9
