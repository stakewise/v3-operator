from dataclasses import dataclass
from typing import NewType

from eth_typing import ChecksumAddress, HexStr

BLSPrivkey = NewType('BLSPrivkey', bytes)
Keystores = NewType('Keystores', dict[HexStr, BLSPrivkey])


@dataclass
class OraclesApproval:
    signatures: bytes
    ipfs_hash: str


@dataclass
class SignatureRotationRequest:
    vault_address: ChecksumAddress
    public_keys: list[HexStr]
    public_key_shards: list[list[HexStr]]
    exit_signature_shards: list[list[HexStr]]
