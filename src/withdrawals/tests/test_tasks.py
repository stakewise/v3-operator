from web3.types import Gwei

from src.withdrawals.tasks import _get_partial_withdrawals_data


def test_get_partial_withdrawals_data():
    validators = {
        '0x1': _to_gwei(40),
    }
    withdrawals_amount = _to_gwei(8)
    expected = {'0x1': _to_gwei(8)}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': _to_gwei(33),
        '0x2': _to_gwei(45),
        '0x3': _to_gwei(55),
        '0x4': _to_gwei(43),
    }
    withdrawals_amount = _to_gwei(18)
    expected = {'0x3': _to_gwei(18)}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': _to_gwei(33),
        '0x2': _to_gwei(40),
        '0x3': _to_gwei(50),
    }

    withdrawals_amount = _to_gwei(20)
    expected = {'0x3': _to_gwei(18), '0x2': _to_gwei(2)}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    validators = {
        '0x1': _to_gwei(33),
        '0x2': _to_gwei(40),
        '0x3': _to_gwei(50),
    }

    withdrawals_amount = _to_gwei(27)
    expected = {'0x3': _to_gwei(18), '0x2': _to_gwei(8), '0x1': _to_gwei(1)}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected

    validators = {}
    withdrawals_amount = 10
    expected = {}
    result = _get_partial_withdrawals_data(validators, withdrawals_amount)
    assert result == expected


def _to_gwei(value) -> Gwei:
    return value * 10**9
