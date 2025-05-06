from src.common.tests.factories import create_validator
from src.withdrawals.tasks import _get_withdrawal_data


def test_get_withdrawal_data():
    validators = [create_validator(balance=_to_gwei(40), public_key='0x1')]
    withdrawals_amount = _to_gwei(8)
    expected = {'0x1': _to_gwei(8)}
    result = _get_withdrawal_data(validators, withdrawals_amount)
    assert result == expected

    validators = [
        create_validator(balance=_to_gwei(33), public_key='0x1'),
        create_validator(balance=_to_gwei(45), public_key='0x2'),
        create_validator(balance=_to_gwei(55), public_key='0x3'),
        create_validator(balance=_to_gwei(43), public_key='0x4'),
    ]
    withdrawals_amount = _to_gwei(18)
    expected = {'0x3': _to_gwei(18)}
    result = _get_withdrawal_data(validators, withdrawals_amount)
    assert result == expected

    validators = [
        create_validator(balance=_to_gwei(33), public_key='0x1'),
        create_validator(balance=_to_gwei(40), public_key='0x2'),
        create_validator(balance=_to_gwei(50), public_key='0x3'),
    ]
    withdrawals_amount = _to_gwei(20)
    expected = {'0x3': _to_gwei(18), '0x2': _to_gwei(2)}
    result = _get_withdrawal_data(validators, withdrawals_amount)
    assert result == expected

    validators = [
        create_validator(balance=_to_gwei(33), public_key='0x1'),
        create_validator(balance=_to_gwei(40), public_key='0x2'),
        create_validator(balance=_to_gwei(50), public_key='0x3'),
    ]
    withdrawals_amount = _to_gwei(27)
    expected = {'0x3': _to_gwei(18), '0x2': _to_gwei(8), '0x1': _to_gwei(1)}
    result = _get_withdrawal_data(validators, withdrawals_amount)
    assert result == expected

    validators = []
    withdrawals_amount = 10
    expected = {}
    result = _get_withdrawal_data(validators, withdrawals_amount)
    assert result == expected

    # validators = [create_validator(balance=35, public_key="0x1")]
    # withdrawals_amount = 10
    # with pytest.raises(AssertionError):
    #     _get_withdrawal_data(validators, withdrawals_amount)


def _to_gwei(value):
    return value * 10**9
