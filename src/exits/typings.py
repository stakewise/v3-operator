import dataclasses
from dataclasses import dataclass
from datetime import datetime

from eth_typing import ChecksumAddress, HexStr


@dataclass
class OraclesApproval:
    signatures: bytes
    ipfs_hash: str
    deadline: datetime


@dataclass
class SignatureRotationRequest:
    vault_address: ChecksumAddress
    public_keys: list[HexStr]
    public_key_shards: list[list[HexStr]]
    exit_signature_shards: list[list[HexStr]]
    deadline: datetime

    def as_json_dict(self) -> dict:
        """
        :return: dict which can be serialized by `json.dumps()`
        """
        res = dataclasses.asdict(self)
        res['deadline'] = int(self.deadline.timestamp())
        return res
