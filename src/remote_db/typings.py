from dataclasses import dataclass

from eth_typing import HexStr


@dataclass
class RemoteDatabaseKeyPair:
    public_key: HexStr
    private_key: HexStr
    nonce: HexStr
