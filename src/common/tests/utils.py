from decimal import Decimal

from web3 import Web3
from web3.types import Gwei, Wei


def ether_to_gwei(value: int | float | Decimal) -> Gwei:
    return Gwei(int(value * 10**9))


def parse_wei(value: str | list | dict) -> Wei:
    if isinstance(value, str):
        number, unit = value.split(' ')
        return Web3.to_wei(number, unit)

    if isinstance(value, list):
        return [parse_wei(value) for value in value]

    if isinstance(value, dict):
        return {key: parse_wei(value) for key, value in value.items()}

    raise ValueError(f'Unsupported type for parse_wei: {type(value)}')
