from dataclasses import dataclass

from eth_typing import HexStr, BlockNumber


@dataclass
class VaultValidator:
    public_key: HexStr
    block_number: BlockNumber
