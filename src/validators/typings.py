from dataclasses import dataclass
from enum import Enum
from typing import NewType

from eth_typing import BlockNumber, BLSSignature, ChecksumAddress, HexStr

BLSPrivkey = NewType('BLSPrivkey', bytes)


@dataclass
class NetworkValidator:
    public_key: HexStr
    block_number: BlockNumber


@dataclass
class ExitSignatureShards:
    public_keys: list[HexStr]
    exit_signatures: list[HexStr]


@dataclass
class Validator:
    public_key: HexStr
    signature: HexStr
    amount_gwei: int
    exit_signature: BLSSignature | None = None
    exit_signature_shards: ExitSignatureShards | None = None

    deposit_data_root: HexStr | None = None


@dataclass
class RelayerValidatorsResponse:
    validators: list[Validator]
    validators_manager_signature: HexStr | None = None


@dataclass
# pylint: disable-next=too-many-instance-attributes
class ApprovalRequest:
    validator_index: int
    vault_address: ChecksumAddress
    validators_root: HexStr
    public_keys: list[HexStr]
    deposit_signatures: list[HexStr]
    public_key_shards: list[list[HexStr]]
    exit_signature_shards: list[list[HexStr]]
    validators_manager_signature: HexStr
    deadline: int

    # legacy
    proof: list[HexStr] | None = None
    # proof_flags: list[bool] | None = None
    # proof_indexes: list[int] | None = None


class ValidatorsRegistrationMode(Enum):
    """
    AUTO mode: validators are registered automatically when vault assets are enough.
    API mode: validators registration is triggered by API request.
    """

    AUTO = 'AUTO'
    API = 'API'


class RelayerTypes:
    DVT = 'DVT'
    DEFAULT = 'DEFAULT'
