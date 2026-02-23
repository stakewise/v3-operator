import logging
from typing import Sequence

from eth_typing import HexStr
from sw_utils import get_v1_withdrawal_credentials, get_v2_withdrawal_credentials
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import Gwei

from src.common.typings import ValidatorType
from src.config.settings import settings
from src.validators.database import NetworkValidatorCrud
from src.validators.execution import get_latest_network_validator_public_keys
from src.validators.keystores.base import BaseKeystore
from src.validators.typings import Validator

logger = logging.getLogger(__name__)


async def get_validators_for_registration(
    keystore: BaseKeystore,
    amounts: list[Gwei],
) -> Sequence[Validator]:
    """Returns list of available validators for registration."""
    available_public_keys = await _filter_nonregistered_public_keys(
        available_public_keys=keystore.public_keys,
        count=len(amounts),
    )
    validators = []
    for amount, public_key in zip(amounts, available_public_keys):
        deposit_data = await keystore.get_deposit_data(public_key=public_key, amount=amount)
        validators.append(
            Validator(
                public_key=Web3.to_hex(deposit_data['pubkey']),
                deposit_signature=Web3.to_hex(deposit_data['signature']),
                amount=Gwei(int(deposit_data['amount'])),
                deposit_data_root=Web3.to_hex(deposit_data['deposit_data_root']),
            )
        )

    return validators


def get_withdrawal_credentials() -> Bytes32:
    """Returns withdrawal credentials based on the validator type."""
    if settings.validator_type == ValidatorType.V1:
        return get_v1_withdrawal_credentials(settings.vault)
    return get_v2_withdrawal_credentials(settings.vault)


async def _filter_nonregistered_public_keys(
    available_public_keys: list[HexStr],
    count: int,
) -> list[HexStr]:
    public_keys: list[HexStr] = []
    latest_network_validator_public_keys = await get_latest_network_validator_public_keys()
    for public_key in available_public_keys:
        if NetworkValidatorCrud().is_validator_registered(public_key):
            continue
        if public_key in latest_network_validator_public_keys:
            continue
        public_keys.append(public_key)
        if len(public_keys) >= count:
            break

    return public_keys
