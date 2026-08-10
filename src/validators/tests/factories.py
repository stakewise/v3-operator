from eth_typing import ChecksumAddress, HexStr
from sw_utils import ValidatorStatus
from sw_utils.tests import faker
from web3.types import Gwei

from src.config.settings import MIN_ACTIVATION_BALANCE_GWEI, settings
from src.validators.typings import ConsensusValidator


def create_consensus_validator(
    public_key: HexStr | None = None,
    index: int | None = None,
    balance: Gwei | None = None,
    status: ValidatorStatus = ValidatorStatus.ACTIVE_ONGOING,
    activation_epoch: int | None = None,
    is_compounding: bool = True,
    withdrawal_address: ChecksumAddress | None = None,
) -> ConsensusValidator:
    # settings.vault is unset in tests that don't use the fake_settings fixture
    withdrawal_address = (
        withdrawal_address or getattr(settings, 'vault', None) or faker.eth_address()
    )
    return ConsensusValidator(
        public_key=public_key or faker.validator_public_key(),
        status=status,
        index=index,
        balance=balance or MIN_ACTIVATION_BALANCE_GWEI,
        withdrawal_credentials=(
            _build_compound_credentials(withdrawal_address)
            if is_compounding
            else _build_non_compound_credentials(withdrawal_address)
        ),
        activation_epoch=activation_epoch,
    )


def _build_non_compound_credentials(withdrawal_address: ChecksumAddress) -> HexStr:
    return HexStr('0x01' + '0' * 22 + withdrawal_address[2:].lower())


def _build_compound_credentials(withdrawal_address: ChecksumAddress) -> HexStr:
    return HexStr('0x02' + '0' * 22 + withdrawal_address[2:].lower())
