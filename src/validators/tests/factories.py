import struct
from contextlib import contextmanager
from random import randbytes
from typing import Any, Callable, Iterator, cast
from unittest import mock

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils import ValidatorStatus
from sw_utils.tests import faker
from web3 import Web3
from web3.datastructures import AttributeDict
from web3.types import EventData, Gwei

from src.config.networks import HOODI, NETWORKS
from src.config.settings import MIN_ACTIVATION_BALANCE_GWEI, settings
from src.validators.database import CheckpointCrud, NetworkValidatorCrud
from src.validators.typings import (
    ConsensusValidator,
    NetworkValidator,
    ValidatorConsolidationData,
)

FORK_EPOCH = 10
FORK_SLOT = FORK_EPOCH * NETWORKS[HOODI].SLOTS_PER_EPOCH


def create_consensus_validator(
    public_key: HexStr | None = None,
    index: int | None = None,
    balance: Gwei | None = None,
    status: ValidatorStatus = ValidatorStatus.ACTIVE_ONGOING,
    activation_epoch: int | None = None,
    is_compounding: bool = True,
    withdrawal_address: ChecksumAddress | None = None,
    pending_balance: Gwei | None = None,
    consolidation_data: ValidatorConsolidationData | None = None,
    # Set to False to build a validator whose consolidation data was not loaded
    with_consolidation_data: bool = True,
) -> ConsensusValidator:
    # settings.vault is unset in tests that don't use the fake_settings fixture
    withdrawal_address = (
        withdrawal_address or getattr(settings, 'vault', None) or faker.eth_address()
    )
    if consolidation_data is None and with_consolidation_data:
        consolidation_data = ValidatorConsolidationData(is_source=False, is_target=False)

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
        pending_balance=pending_balance,
        consolidation_data=consolidation_data,
    )


def create_deposit_event(
    public_key: HexStr | None = None,
    withdrawal_credentials_prefix: bytes = b'\x01',
    block_number: int | None = None,
    amount_gwei: int = 32 * 10**9,
) -> EventData:
    """`DepositEvent` of the validators registry, the signature is random."""
    public_key = public_key or faker.validator_public_key()
    return cast(
        EventData,
        AttributeDict(
            {
                'blockNumber': BlockNumber(block_number or faker.random_int(10, 100000)),
                'args': AttributeDict(
                    {
                        'pubkey': Web3.to_bytes(hexstr=public_key),
                        'withdrawal_credentials': (
                            withdrawal_credentials_prefix + b'\x00' * 11 + randbytes(20)
                        ),
                        'amount': struct.pack('<Q', amount_gwei),
                        'signature': randbytes(96),
                        'index': struct.pack('<Q', 0),
                    }
                ),
            }
        ),
    )


def get_public_key(event: EventData) -> HexStr:
    return Web3.to_hex(event['args']['pubkey'])


def save_network_validator(block_number: BlockNumber, public_key: HexStr | None = None) -> HexStr:
    public_key = public_key or faker.validator_public_key()
    NetworkValidatorCrud().save_network_validators(
        [NetworkValidator(public_key=public_key, block_number=block_number)]
    )
    return public_key


def set_network_validators_checkpoint(block_number: BlockNumber) -> None:
    CheckpointCrud().update_checkpoint(CheckpointCrud.CHECKPOINT_NETWORK_VALIDATORS, block_number)


@contextmanager
def patch_deposit_signature(is_valid: bool | Callable[..., bool] = True) -> Iterator[None]:
    options: dict[str, Any] = (
        {'side_effect': is_valid} if callable(is_valid) else {'return_value': is_valid}
    )
    with mock.patch('src.validators.event_processors.is_valid_deposit_data_signature', **options):
        yield


@contextmanager
def patch_block_slot(slot_by_block: Callable[[int], int]) -> Iterator[mock.AsyncMock]:
    with mock.patch(
        'src.validators.event_processors.calc_slot_by_block_number', side_effect=slot_by_block
    ) as slot_mock:
        yield slot_mock


@contextmanager
def patch_tail_events(events: list[EventData]) -> Iterator[mock.AsyncMock]:
    with mock.patch(
        'src.validators.event_processors.validators_registry_contract.get_deposit_events',
        return_value=events,
    ) as events_mock:
        yield events_mock


def _build_non_compound_credentials(withdrawal_address: ChecksumAddress) -> HexStr:
    return HexStr('0x01' + '0' * 22 + withdrawal_address[2:].lower())


def _build_compound_credentials(withdrawal_address: ChecksumAddress) -> HexStr:
    return HexStr('0x02' + '0' * 22 + withdrawal_address[2:].lower())
