from dataclasses import dataclass
from typing import NewType

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from multiproof import StandardMerkleTree
from sw_utils.typings import Bytes32

BLSPrivkey = NewType('BLSPrivkey', bytes)
Keystores = NewType('Keystores', dict[HexStr, BLSPrivkey])


@dataclass
class NetworkValidator:
    public_key: HexStr
    block_number: BlockNumber


@dataclass
class Validator:
    deposit_data_index: int
    public_key: HexStr
    signature: HexStr


@dataclass
class DepositData:
    validators: list[Validator]
    tree: StandardMerkleTree


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
    address: ChecksumAddress
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
class KeeperApprovalParams:
    validatorsRegistryRoot: HexStr | Bytes32
    validators: HexStr | bytes
    signatures: HexStr | bytes
    exitSignaturesIpfsHash: str


@dataclass
class KeystoreFile:
    name: str
    password: str
