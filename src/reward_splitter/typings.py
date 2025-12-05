from dataclasses import dataclass

from eth_typing import ChecksumAddress
from web3.types import Wei


@dataclass
class RewardSplitterShareHolder:
    address: ChecksumAddress
    earned_vault_assets: Wei


@dataclass
class RewardSplitter:
    address: ChecksumAddress
    vault: ChecksumAddress
    shareholders: list[RewardSplitterShareHolder]
