from src.commands.consolidate import _split_validators
from src.common.tests.factories import create_validator


def test_split_validators():
    validator_1 = create_validator(balance=32)
    validator_2 = create_validator(balance=33)
    validator_3 = create_validator(balance=33)
    to_from = _split_validators([validator_1, validator_2])
    assert to_from == [(validator_1.public_key, validator_2.public_key)]

    to_from = _split_validators([validator_1, validator_2, validator_3])
    assert to_from == [
        (validator_1.public_key, validator_2.public_key),
        (validator_1.public_key, validator_3.public_key),
    ]

    validators = [create_validator(balance=32) for x in range(64)]
    to_from = _split_validators(validators)
    assert to_from == [(validators[0].public_key, v.public_key) for v in validators[1:]]

    validators = [create_validator(balance=32 * 10**9) for x in range(67)]

    to_from = _split_validators(validators)
    assert len([pair for pair in to_from if pair[0] == validators[0].public_key]) == 63
    assert len([pair for pair in to_from if pair[0] == validators[1].public_key]) == 2
    assert to_from == [(validators[0].public_key, v.public_key) for v in validators[2:65]] + [
        (validators[1].public_key, v.public_key) for v in validators[65:67]
    ]
