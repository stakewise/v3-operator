from dataclasses import dataclass
from enum import Enum
from typing import NewType

from eth_typing import BlockNumber, BLSSignature, ChecksumAddress, HexStr
from sw_utils import ValidatorStatus
from web3.types import Gwei, Wei

BLSPrivkey = NewType('BLSPrivkey', bytes)


@dataclass
class NetworkValidator:
    public_key: HexStr
    block_number: BlockNumber


@dataclass
class VaultValidator:
    vault_address: HexStr
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
    amount: Gwei
    exit_signature: BLSSignature | None = None
    exit_signature_shards: ExitSignatureShards | None = None

    deposit_data_root: HexStr | None = None


@dataclass
class ConsensusValidator:
    index: int
    public_key: HexStr
    balance: Gwei
    withdrawal_credentials: HexStr
    status: ValidatorStatus
    activation_epoch: int

    @property
    def is_compounding(self) -> bool:
        return self.withdrawal_credentials.startswith('0x02')


@dataclass
class V2ValidatorEventData:
    public_key: HexStr
    amount: Wei


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
    amounts: list[int] | None = None


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


@dataclass
class ConsolidationRequest:
    from_public_keys: list[HexStr]
    to_public_keys: list[HexStr]
    vault_address: ChecksumAddress
