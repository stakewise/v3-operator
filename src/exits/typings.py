import dataclasses
from dataclasses import dataclass

from eth_typing import ChecksumAddress, HexStr


@dataclass
class SignatureRotationRequest:
    vault_address: ChecksumAddress
    public_keys: list[HexStr]
    public_key_shards: list[list[HexStr]]
    exit_signature_shards: list[list[HexStr]]
    deadline: int

    def as_json_dict(self) -> dict:
        """
        :return: dict which can be serialized by `json.dumps()`
        """
        res = dataclasses.asdict(self)
        return res
