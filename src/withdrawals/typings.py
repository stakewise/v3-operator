from dataclasses import dataclass

from eth_typing import BlockNumber, HexStr
from web3.types import Wei


@dataclass
class WithdrawalEvent:
    public_key: HexStr
    amount: Wei
    block_number: BlockNumber
