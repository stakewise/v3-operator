from sw_utils.tests import faker
from web3 import Web3

from src.common.typings import ValidatorType
from src.config.networks import HOODI
from src.config.settings import (
    MAX_EFFECTIVE_BALANCE_GWEI,
    MIN_ACTIVATION_BALANCE_GWEI,
    settings,
)
from src.validators.tasks import _get_deposits_amounts, _get_funding_amounts


def test_get_deposits_amounts():
    assert _get_deposits_amounts(0, ValidatorType.V1) == []
    assert _get_deposits_amounts(0, ValidatorType.V2) == []

    assert _get_deposits_amounts(Web3.to_wei(32, 'ether'), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]
    assert _get_deposits_amounts(Web3.to_wei(32, 'ether'), ValidatorType.V2) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]

    assert _get_deposits_amounts(Web3.to_wei(33, 'ether'), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_deposits_amounts(Web3.to_wei(33, 'ether'), ValidatorType.V2) == [_to_gwei(33)]

    assert _get_deposits_amounts(Web3.to_wei(64, 'ether'), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_deposits_amounts(Web3.to_wei(64, 'ether'), ValidatorType.V2) == [_to_gwei(64)]

    assert _get_deposits_amounts(Web3.to_wei(66, 'ether'), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_deposits_amounts(Web3.to_wei(66, 'ether'), ValidatorType.V2) == [_to_gwei(66)]

    assert (
        _get_deposits_amounts(Web3.to_wei(2048, 'ether'), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert _get_deposits_amounts(Web3.to_wei(2048, 'ether'), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI
    ]

    assert (
        _get_deposits_amounts(Web3.to_wei(2050, 'ether'), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert (
        _get_deposits_amounts(Web3.to_wei(2081, 'ether'), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 65
    )
    assert _get_deposits_amounts(Web3.to_wei(2050, 'ether'), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI
    ]

    assert _get_deposits_amounts(Web3.to_wei(2081, 'ether'), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI,
        _to_gwei(33),
    ]
    assert (
        _get_deposits_amounts(Web3.to_wei(4096, 'ether'), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 128
    )
    assert _get_deposits_amounts(Web3.to_wei(4096, 'ether'), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI,
        MAX_EFFECTIVE_BALANCE_GWEI,
    ]


def test_get_funding_amounts(data_dir):
    settings.set(vaults=[], data_dir=data_dir, network=HOODI)
    public_key_1 = faker.eth_address()
    public_key_2 = faker.eth_address()

    data = _get_funding_amounts({public_key_1: _to_gwei(32)}, funding_amount=_to_gwei(1))
    assert data == {public_key_1: _to_gwei(1)}

    data = _get_funding_amounts({public_key_1: _to_gwei(32)}, funding_amount=_to_gwei(100))
    assert data == {public_key_1: _to_gwei(100)}

    data = _get_funding_amounts(
        {public_key_1: _to_gwei(32), public_key_2: _to_gwei(33)}, funding_amount=_to_gwei(2100)
    )
    assert data == {
        public_key_2: _to_gwei(2015),
        public_key_1: _to_gwei(85),
    }

    data = _get_funding_amounts(
        {public_key_1: _to_gwei(2038), public_key_2: _to_gwei(32)}, funding_amount=_to_gwei(10.5)
    )
    assert data == {
        public_key_1: _to_gwei(10),
    }

    data = _get_funding_amounts(
        {public_key_1: _to_gwei(32), public_key_2: _to_gwei(33)}, funding_amount=_to_gwei(2100.5)
    )
    assert data == {
        public_key_2: _to_gwei(2015),
        public_key_1: _to_gwei(85.5),
    }


def _to_gwei(value):
    return value * 10**9
