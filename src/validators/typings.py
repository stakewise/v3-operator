from dataclasses import dataclass
from enum import Enum
from typing import NewType, Sequence

from eth_typing import BlockNumber, BLSSignature, ChecksumAddress, HexStr
from multiproof import MultiProof, StandardMerkleTree

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
    deposit_data_index: int | None = None
    exit_signature: BLSSignature | None = None
    exit_signature_shards: ExitSignatureShards | None = None

    def copy(self) -> 'Validator':
        return Validator(
            public_key=self.public_key,
            signature=self.signature,
            amount_gwei=self.amount_gwei,
            deposit_data_index=self.deposit_data_index,
            exit_signature_shards=self.exit_signature_shards,
        )


@dataclass
class RelayerValidatorsResponse:
    validators: list[Validator]
    validators_manager_signature: HexStr | None = None
    multi_proof: MultiProof[tuple[bytes, int]] | None = None


@dataclass
class DepositData:
    validators: Sequence[Validator]
    tree: StandardMerkleTree

    @property
    def public_keys(self) -> list[HexStr]:
        return [v.public_key for v in self.validators]


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
