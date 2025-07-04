from dataclasses import dataclass

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.types import HexBytes, Wei

from src.common.typings import HarvestParams


@dataclass
class RewardSplitterShareHolder:
    address: ChecksumAddress
    earned_vault_assets: Wei


@dataclass
class RewardSplitter:
    address: ChecksumAddress
    vault: ChecksumAddress
    shareholders: list[RewardSplitterShareHolder]


@dataclass
class ExitRequest:
    position_ticket: int
    timestamp: int
    exit_queue_index: int | None
    is_claimable: bool
    receiver: ChecksumAddress
    exited_assets: Wei
    total_assets: Wei

    @property
    def can_be_claimed(self) -> bool:
        return self.is_claimable and self.exited_assets == self.total_assets

    @staticmethod
    def from_graph(data: dict) -> 'ExitRequest':
        exit_queue_index = (
            int(data['exitQueueIndex']) if data.get('exitQueueIndex') is not None else None
        )
        return ExitRequest(
            position_ticket=int(data['positionTicket']),
            timestamp=int(data['timestamp']),
            exit_queue_index=exit_queue_index,
            is_claimable=data['isClaimable'],
            receiver=Web3.to_checksum_address(data['receiver']),
            exited_assets=Wei(int(data['exitedAssets'])),
            total_assets=Wei(int(data['totalAssets'])),
        )


@dataclass
class Vault:
    address: ChecksumAddress
    can_harvest: bool
    rewards_root: HexBytes
    proof_reward: Wei
    proof_unlocked_mev_reward: Wei
    proof: list[HexBytes]

    @property
    def harvest_params(self) -> HarvestParams:
        return HarvestParams(
            rewards_root=self.rewards_root,
            reward=self.proof_reward,
            unlocked_mev_reward=self.proof_unlocked_mev_reward,
            proof=self.proof,
        )
