from dataclasses import dataclass
from enum import Enum
from typing import NewType

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
    deposit_data_index: int
    public_key: HexStr
    signature: HexStr
    exit_signature: BLSSignature | None = None


@dataclass
class DepositData:
    validators: list[Validator]
    tree: StandardMerkleTree

    @property
    def public_keys(self) -> list[HexStr]:
        return [v.public_key for v in self.validators]


@dataclass
class ExitSignatureShards:
    public_keys: list[HexStr]
    exit_signatures: list[HexStr]  # encrypted exit signature shards


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
    proof: list[HexStr]
    proof_flags: list[bool]
    proof_indexes: list[int]


@dataclass
class KeeperApprovalParams:
    validatorsRegistryRoot: HexStr | Bytes32
    validators: HexStr | bytes
    signatures: HexStr | bytes
    exitSignaturesIpfsHash: str


class ValidatorsRegistrationMode(Enum):
    AUTO = 'AUTO'
    API = 'API'
