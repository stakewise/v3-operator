from sw_utils.tests import faker

from src.common.tests.utils import ether_to_gwei
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

    assert _get_deposits_amounts(ether_to_gwei(32), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]
    assert _get_deposits_amounts(ether_to_gwei(32), ValidatorType.V2) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]

    assert _get_deposits_amounts(ether_to_gwei(33), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_deposits_amounts(ether_to_gwei(33), ValidatorType.V2) == [ether_to_gwei(33)]

    assert _get_deposits_amounts(ether_to_gwei(64), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_deposits_amounts(ether_to_gwei(64), ValidatorType.V2) == [ether_to_gwei(64)]

    assert _get_deposits_amounts(ether_to_gwei(66), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert _get_deposits_amounts(ether_to_gwei(66), ValidatorType.V2) == [ether_to_gwei(66)]

    assert (
        _get_deposits_amounts(ether_to_gwei(2048), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert _get_deposits_amounts(ether_to_gwei(2048), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI
    ]

    assert (
        _get_deposits_amounts(ether_to_gwei(2050), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert (
        _get_deposits_amounts(ether_to_gwei(2081), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 65
    )
    assert _get_deposits_amounts(ether_to_gwei(2050), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI
    ]

    assert _get_deposits_amounts(ether_to_gwei(2081), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI,
        ether_to_gwei(33),
    ]
    assert (
        _get_deposits_amounts(ether_to_gwei(4096), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 128
    )
    assert _get_deposits_amounts(ether_to_gwei(4096), ValidatorType.V2) == [
        MAX_EFFECTIVE_BALANCE_GWEI,
        MAX_EFFECTIVE_BALANCE_GWEI,
    ]


def test_get_funding_amounts(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    public_key_1 = faker.eth_address()
    public_key_2 = faker.eth_address()

    data = _get_funding_amounts({public_key_1: ether_to_gwei(32)}, vault_assets=ether_to_gwei(1))
    assert data == {public_key_1: ether_to_gwei(1)}

    data = _get_funding_amounts({public_key_1: ether_to_gwei(32)}, vault_assets=ether_to_gwei(100))
    assert data == {public_key_1: ether_to_gwei(100)}

    data = _get_funding_amounts(
        {public_key_1: ether_to_gwei(32), public_key_2: ether_to_gwei(33)},
        vault_assets=ether_to_gwei(2100),
    )
    assert data == {
        public_key_2: ether_to_gwei(2015),
        public_key_1: ether_to_gwei(85),
    }

    data = _get_funding_amounts(
        {public_key_1: ether_to_gwei(2038), public_key_2: ether_to_gwei(32)},
        vault_assets=ether_to_gwei(10.5),
    )
    assert data == {
        public_key_1: ether_to_gwei(10),
    }

    data = _get_funding_amounts(
        {public_key_1: ether_to_gwei(32), public_key_2: ether_to_gwei(33)},
        vault_assets=ether_to_gwei(2100.5),
    )
    assert data == {
        public_key_2: ether_to_gwei(2015),
        public_key_1: ether_to_gwei(85.5),
    }
