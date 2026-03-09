from dataclasses import dataclass

from eth_typing import ChecksumAddress
from web3.types import Wei


@dataclass
class EligibleOperator:
    """Operator eligible to register or fund validators."""

    address: ChecksumAddress
    amount: Wei
