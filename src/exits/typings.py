from dataclasses import dataclass

from eth_typing import ChecksumAddress, HexStr


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
