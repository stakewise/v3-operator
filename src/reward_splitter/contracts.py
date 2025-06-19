import logging

from eth_typing import ChecksumAddress, HexStr

from src.common.contracts import ContractWrapper
from src.common.typings import HarvestParams

logger = logging.getLogger(__name__)


SOLIDITY_UINT256_MAX = 2**256 - 1


class RewardSplitterContract(ContractWrapper):
    def encoder(self) -> 'RewardSplitterEncoder':
        return RewardSplitterEncoder(self)


class RewardSplitterEncoder:
    """
    Helper class to encode RewardSplitter contract ABI calls
    """

    def __init__(self, contract: RewardSplitterContract):
        self.contract = contract

    def update_vault_state(self, harvest_params: HarvestParams) -> HexStr:
        return self.contract.encode_abi(
            fn_name='updateVaultState',
            args=[
                (
                    harvest_params.rewards_root,
                    harvest_params.reward,
                    harvest_params.unlocked_mev_reward,
                    harvest_params.proof,
                ),
            ],
        )

    def enter_exit_queue_on_behalf(self, rewards: int | None, address: ChecksumAddress) -> HexStr:
        rewards = rewards or SOLIDITY_UINT256_MAX
        return self.contract.encode_abi(
            fn_name='enterExitQueueOnBehalf',
            args=[rewards, address],
        )

    def claim_exited_assets_on_behalf(
        self, position_ticket: int, timestamp: int, exit_queue_index: int
    ) -> HexStr:
        return self.contract.encode_abi(
            fn_name='claimExitedAssetsOnBehalf',
            args=[position_ticket, timestamp, exit_queue_index],
        )
