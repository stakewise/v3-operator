from dataclasses import dataclass
from typing import NewType

from Cryptodome.PublicKey import RSA
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils.typings import Bytes32

BLSPrivkey = NewType('BLSPrivkey', bytes)


@dataclass
class NetworkValidator:
    public_key: HexStr
    block_number: BlockNumber


@dataclass
class ValidatorsRoot:
    root: HexStr
    ipfs_hash: str
    block_number: BlockNumber


@dataclass
class DepositData:
    validator_index: int
    public_key: HexStr
    signature: HexStr


@dataclass
class Oracles:
    threshold: int
    addresses: list[ChecksumAddress]
    rsa_public_keys: list[RSA.RsaKey]
    endpoints: list[str]


@dataclass
class ExitSignatureShards:
    public_keys: list[HexStr]
    exit_signatures: list[HexStr]


@dataclass
class OraclesApproval:
    validators_registry_root: Bytes32
    signatures: bytes
    ipfs_hash: str


@dataclass
class OracleApproval:
    signature: bytes
    ipfs_hash: str


@dataclass
class ApprovalRequest:
    validator_index: int
    vault_address: ChecksumAddress
    validators_root: HexStr
    public_keys: list[HexStr]
    deposit_signatures: list[HexStr]
    public_key_shards: list[list[HexStr]]
    exit_signature_shards: list[list[HexStr]]


@dataclass
class SingleValidatorRegistration:
    vault: ChecksumAddress
    validatorsRegistryRoot: HexStr | Bytes32
    validator: HexStr | bytes
    signatures: HexStr | bytes
    exitSignatureIpfsHash: str
    proof: list[str | HexStr | bytes]


@dataclass
class MultipleValidatorRegistration:
    vault: ChecksumAddress
    validatorsRegistryRoot: HexStr | Bytes32
    validators: HexStr | bytes
    signatures: HexStr | bytes
    exitSignatureIpfsHash: str
    indexes: list[int]
    proofFlags: list[bool]
    proof: list[str | HexStr | bytes]
