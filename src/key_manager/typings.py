from dataclasses import dataclass

from eth_typing import HexStr


@dataclass
class DatabaseKeyRecord:
    public_key: HexStr
    private_key: str
    nonce: str
