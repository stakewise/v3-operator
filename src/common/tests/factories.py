import random
import string

from eth_typing import HexStr
from sw_utils.tests import faker

from src.common.typings import Validator, ValidatorType


def create_validator(
    public_key: HexStr | None = None,
    index: int | None = None,
    balance: int | None = None,
    status: int | None = None,
    withdrawal_credentials: str | None = None,
    validator_type: ValidatorType | None = None,
) -> Validator:
    # produce cid V1
    if not withdrawal_credentials:
        if validator_type == ValidatorType.ONE:
            withdrawal_credentials = '0x01' + ''.join(
                random.choices('abcdef' + string.digits, k=62)
            )
        else:
            withdrawal_credentials = '0x02' + ''.join(
                random.choices('abcdef' + string.digits, k=62)
            )

    return Validator(
        public_key=public_key or faker.eth_address(),
        index=index or random.randint(1, 10000),
        balance=balance or random.randint(1, 10000),
        status=status,
        withdrawal_credentials=withdrawal_credentials,
    )
