from dataclasses import dataclass

from eth_typing import ChecksumAddress, HexStr


@dataclass
class RemoteDatabaseKeyPair:
    vault: ChecksumAddress
    public_key: HexStr
    private_key: HexStr
    nonce: HexStr
    parent_public_key: HexStr | None = None
