from dataclasses import dataclass

from eth_typing import BlockNumber, HexStr
from web3.types import Gwei, Wei


@dataclass
class WithdrawalEvent:
    public_key: HexStr
    amount: Wei
    block_number: BlockNumber


@dataclass(frozen=True)
class ExitQueueAssets:
    # Shortfall to withdraw now
    missing: Gwei
    # Value of the queued exit shares, the base for the withdrawal buffer
    total: Gwei
