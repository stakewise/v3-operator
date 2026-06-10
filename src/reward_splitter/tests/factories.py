from eth_typing import ChecksumAddress
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.reward_splitter.typings import RewardSplitter, RewardSplitterShareHolder


def create_reward_splitter(
    address: ChecksumAddress | None = None,
    vault: ChecksumAddress | None = None,
    shareholders_earned_assets: list[Wei] | None = None,
) -> RewardSplitter:
    if shareholders_earned_assets is None:
        shareholders_earned_assets = [Wei(Web3.to_wei('1', 'ether'))]

    return RewardSplitter(
        address=address or faker.eth_address(),
        vault=vault or faker.eth_address(),
        shareholders=[
            RewardSplitterShareHolder(
                address=faker.eth_address(),
                earned_vault_assets=earned,
            )
            for earned in shareholders_earned_assets
        ],
    )
