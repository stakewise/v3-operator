from decimal import Decimal

from web3.types import Gwei


def ether_to_gwei(value: int | float | Decimal) -> Gwei:
    return Gwei(value * 10**9)
