from sw_utils.tests import faker

from src.commands.consolidate import _split_validators


def test_split_validators():
    public_key_1 = faker.eth_address()
    public_key_2 = faker.eth_address()
    public_key_3 = faker.eth_address()
    public_key_4 = faker.eth_address()

    to_from = _split_validators({public_key_1: _to_gwei(32), public_key_2: _to_gwei(33)})
    assert to_from == [(public_key_2, public_key_1)]

    to_from = _split_validators(
        {public_key_1: _to_gwei(32), public_key_2: _to_gwei(33), public_key_3: _to_gwei(33)}
    )
    assert to_from == [
        (public_key_2, public_key_1),
        (public_key_2, public_key_3),
    ]

    to_from = _split_validators(
        {
            public_key_1: _to_gwei(2000),
            public_key_2: _to_gwei(32),
            public_key_3: _to_gwei(33),
        }
    )
    assert to_from == [
        (public_key_1, public_key_2),
    ]

    to_from = _split_validators(
        {
            public_key_1: _to_gwei(2000),
            public_key_2: _to_gwei(32),
            public_key_3: _to_gwei(33),
            public_key_4: _to_gwei(2000),
        }
    )
    assert to_from == [
        (public_key_1, public_key_2),
        (public_key_4, public_key_3),
    ]

    validators = {faker.eth_address(): _to_gwei(32) for _ in range(64)}
    to_from = _split_validators(validators)
    first_key = list(validators.keys())[0]

    assert to_from == [(first_key, key) for key in validators.keys() if key != first_key]

    validators = {faker.eth_address(): _to_gwei(32 + i) for i in range(67)}
    to_from = _split_validators(validators)
    assert len([pair for pair in to_from if pair[0] == list(validators.keys())[-1]]) == 38
    assert len([pair for pair in to_from if pair[0] == list(validators.keys())[-2]]) == 23
    assert len([pair for pair in to_from if pair[0] == list(validators.keys())[-3]]) == 3
    assert len([pair for pair in to_from if pair[0] == list(validators.keys())[-4]]) == 0


def _to_gwei(value):
    return value * 10**9
