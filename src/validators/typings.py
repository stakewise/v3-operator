from dataclasses import dataclass
from enum import Enum
from typing import NewType, Sequence

from eth_typing import BlockNumber, BLSSignature, ChecksumAddress, HexStr
from multiproof import StandardMerkleTree
from sw_utils.typings import Bytes32

BLSPrivkey = NewType('BLSPrivkey', bytes)


@dataclass
class NetworkValidator:
    public_key: HexStr
    block_number: BlockNumber


@dataclass
class Validator:
    public_key: HexStr
    signature: HexStr
    amount_gwei: int


@dataclass
class DepositDataValidator(Validator):
    deposit_data_index: int
    deposit_data_root: HexStr


@dataclass
class RelayerValidator(Validator):
    exit_signature: BLSSignature


@dataclass
class RelayerValidatorsResponse:
    validators: list[RelayerValidator]
    validators_manager_signature: HexStr


@dataclass
class DepositData:
    validators: Sequence[DepositDataValidator]
    tree: StandardMerkleTree

    @property
    def public_keys(self) -> list[HexStr]:
        return [v.public_key for v in self.validators]


@dataclass
class ExitSignatureShards:
    public_keys: list[HexStr]
    exit_signatures: list[HexStr]


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
    deadline: int
    proof: list[HexStr] | None
    proof_flags: list[bool] | None
    proof_indexes: list[int] | None
    validators_manager_signature: HexStr | None = None


@dataclass
class KeeperApprovalParams:
    validatorsRegistryRoot: HexStr | Bytes32
    validators: HexStr | bytes
    signatures: HexStr | bytes
    exitSignaturesIpfsHash: str


class ValidatorsRegistrationMode(Enum):
    """
    AUTO mode: validators are registered automatically when vault assets are enough.
    API mode: validators registration is triggered by API request.
    """

    AUTO = 'AUTO'
    API = 'API'
