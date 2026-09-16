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
    # Net shortfall to request now: queue value minus vault balance, in-flight withdrawals
    # and exiting validators, plus osToken redemptions.
    missing: Gwei
    # Whole remaining queue value ignoring in-flight coverage; it keeps accruing rewards,
    # so it is the base for the withdrawal buffer.
    total: Gwei
