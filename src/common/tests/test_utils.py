from decimal import Decimal

from src.common.utils import round_down


def test_round_down():
    assert round_down(100, 2) == Decimal('100.00')
    assert round_down(Decimal('100.123'), 2) == Decimal('100.12')
    assert round_down(Decimal('100.999'), 2) == Decimal('100.99')
