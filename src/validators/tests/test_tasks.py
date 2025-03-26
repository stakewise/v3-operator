from src.common.tests.factories import create_validator
from src.common.typings import ValidatorType
from src.validators.tasks import _get_topup_data


def test_get_topup_data():
    validator_1 = create_validator(balance=_to_gwei(32), validator_type=ValidatorType.TWO)
    validator_2 = create_validator(balance=_to_gwei(33), validator_type=ValidatorType.TWO)
    create_validator(balance=_to_gwei(35), validator_type=ValidatorType.ONE)

    data = _get_topup_data([validator_1], amount=_to_gwei(1))
    assert data == {validator_1.public_key: _to_gwei(1)}

    data = _get_topup_data([validator_1], amount=_to_gwei(100))
    assert data == {validator_1.public_key: _to_gwei(100)}

    data = _get_topup_data([validator_1, validator_2], amount=_to_gwei(2100))
    assert data == {
        validator_2.public_key: _to_gwei(2015),
        validator_1.public_key: _to_gwei(85),
    }


def _to_gwei(value):
    return value * 10**9
