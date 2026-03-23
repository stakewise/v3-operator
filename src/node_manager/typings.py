from dataclasses import dataclass

from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from web3.types import Wei


@dataclass
class EligibleOperator:
    """Operator eligible to register or fund validators."""

    address: ChecksumAddress
    amount: Wei


@dataclass
class OperatorStateUpdateParams:
    """Parameters for updateOperatorState contract call."""

    total_assets: int
    cum_penalty_assets: int
    cum_earned_fee_shares: int
    proof: list[HexBytes]
