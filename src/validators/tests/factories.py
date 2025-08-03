import random
import string

from eth_typing import HexStr
from sw_utils import ValidatorStatus
from sw_utils.tests import faker
from web3.types import Gwei

from src.config.settings import MIN_ACTIVATION_BALANCE_GWEI
from src.validators.typings import ConsensusValidator


def fake_non_compound_credentials() -> HexStr:
    return HexStr('0x01' + '0' * 22 + ''.join(random.choices('abcdef' + string.digits, k=40)))


def fake_compound_credentials() -> HexStr:
    return HexStr('0x02' + '0' * 22 + ''.join(random.choices('abcdef' + string.digits, k=40)))


def create_consensus_validator(
    public_key: HexStr | None = None,
    index: int | None = None,
    balance: Gwei | None = None,
    status: ValidatorStatus | None = None,
    activation_epoch: int | None = None,
    is_compounding: bool = True,
) -> ConsensusValidator:
    return ConsensusValidator(
        public_key=public_key or faker.validator_public_key(),
        status=status,
        index=index,
        balance=balance or MIN_ACTIVATION_BALANCE_GWEI,
        withdrawal_credentials=(
            fake_compound_credentials() if is_compounding else fake_non_compound_credentials()
        ),
        activation_epoch=activation_epoch,
    )
