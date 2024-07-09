from eth_typing import HexStr
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, EventData, Wei

from src.common.clients import execution_client
from src.common.contracts import ContractWrapper
from src.config.settings import settings
from src.eigenlayer.typings import DelayedWithdrawal, QueuedWithdrawal, ValidatorInfo


class EigenPodContract(ContractWrapper):
    abi_path = 'abi/eigenlayer/IEigenPod.json'

    def __init__(self, address):
        self._address = address

    @property
    def contract_address(self) -> ChecksumAddress:
        return self._address

    async def get_validator_restaked_indexes(
        self,
        from_block: BlockNumber | None = None,
        to_block: BlockNumber | None = None,
    ) -> list[int]:
        """Fetches the validator approval events."""
        from_block = from_block or settings.network_config.KEEPER_GENESIS_BLOCK
        to_block = to_block or await execution_client.eth.get_block_number()
        events = await self._get_events(
            self.events.ValidatorRestaked,  # type: ignore
            from_block=from_block or settings.network_config.KEEPER_GENESIS_BLOCK,
            to_block=to_block or await execution_client.eth.get_block_number(),
        )
        return [int(event['args']['validatorIndex']) for event in events]

    async def get_validator_pubkey_to_info(
        self, public_key: HexStr, block_number: BlockNumber
    ) -> ValidatorInfo:
        data = await self.contract.functions.validatorPubkeyToInfo(public_key).call(
            block_identifier=block_number
        )
        return ValidatorInfo(*data)

    async def get_last_full_withdrawal_redeemed_event(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> EventData:
        return await self._get_last_event(
            event=self.events.FullWithdrawalRedeemed,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )

    async def get_last_partial_withdrawal_redeemed_event(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> EventData:
        return await self._get_last_event(
            event=self.events.PartialWithdrawalRedeemed,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )

    async def get_delayed_withdrawal_router(self, block_number: BlockNumber) -> ChecksumAddress:
        """"""
        address = await self.contract.functions.delayedWithdrawalRouter().call(
            block_identifier=block_number
        )
        return Web3.to_checksum_address(address)


class DelayedWithdrawalRouterContract(ContractWrapper):
    abi_path = 'abi/eigenlayer/IDelayedWithdrawalRouter.json'

    def __init__(self, address):
        self._address = address

    @property
    def contract_address(self) -> ChecksumAddress:
        return self._address

    async def get_claimable_user_delayed_withdrawals(
        self, address: ChecksumAddress, block_number: BlockNumber
    ) -> list[DelayedWithdrawal]:
        """"""
        data = await self.contract.functions.getClaimableUserDelayedWithdrawals(address).call(
            block_identifier=block_number
        )
        return [DelayedWithdrawal(*item) for item in data]


class EigenPodManagerContract(ContractWrapper):
    abi_path = 'abi/eigenlayer/IEigenPodManager.json'
    settings_key = 'EIGENLAYER_POD_MANAGER_CONTRACT_ADDRESS'

    async def get_last_pod_shares_updated_event(
        self, pod_owner: ChecksumAddress, from_block: BlockNumber, to_block: BlockNumber
    ) -> EventData:
        return await self._get_last_event(
            event=self.events.PodSharesUpdated,  # type: ignore
            from_block=from_block,
            to_block=to_block,
            argument_filters={'podOwner': pod_owner},
        )

    async def get_beacon_chain_oracle(self, block_number: BlockNumber) -> ChecksumAddress:
        """"""
        address = await self.contract.functions.beaconChainOracle().call(
            block_identifier=block_number
        )
        return Web3.to_checksum_address(address)

    async def get_pod_shares(self, pod_owner: ChecksumAddress, block_number: BlockNumber) -> Wei:
        """"""
        shares = await self.contract.functions.podOwnerShares(pod_owner).call(
            block_identifier=block_number
        )
        return Wei(shares)


class BeaconChainOracleContract(ContractWrapper):
    abi_path = 'abi/eigenlayer/IBeaconChainOracle.json'

    def __init__(self, address):
        self._address = address

    @property
    def contract_address(self) -> ChecksumAddress:
        return self._address

    async def get_last_oracle_update_event(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> EventData:
        return await self._get_last_event(
            event=self.events.EigenLayerBeaconOracleUpdate,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )


class DelegationManagerContract(ContractWrapper):
    abi_path = 'abi/eigenlayer/IDelegationManager.json'
    settings_key = 'EIGENLAYER_DELEGATION_MANAGER_CONTRACT_ADDRESS'

    async def get_withdrawal_queued_events(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[QueuedWithdrawal]:
        events = await self._get_events(
            event=self.events.WithdrawalQueued,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )
        return [QueuedWithdrawal(*event['args']['withdrawal'].values()) for event in events]

    async def get_withdrawal_completed_events(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[QueuedWithdrawal]:
        events = await self._get_events(
            event=self.events.WithdrawalCompleted,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )
        return [QueuedWithdrawal(*event['args']['withdrawalRoot']) for event in events]

    # async def get_last_withdrawal_queued_event(
    #     self, from_block: BlockNumber, to_block: BlockNumber
    # ) -> EventData:
    #     return await self._get_last_event(
    #         event=self.events.WithdrawalQueued, from_block=from_block, to_block=to_block
    #     )

    async def get_staker_undelegated_events(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[EventData]:
        events = await self._get_events(
            event=self.events.StakerUndelegated,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )
        return events

    async def get_staker_force_undelegated_events(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[EventData]:
        events = await self._get_events(
            event=self.events.StakerForceUndelegated,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )
        return events

    async def get_min_withdrawal_delay_blocks(self, block_number: BlockNumber) -> int:
        """"""
        return await self.contract.functions.minWithdrawalDelayBlocks().call(
            block_identifier=block_number
        )

    async def get_strategy_withdrawal_delay_blocks(
        self, strategy: ChecksumAddress, block_number: BlockNumber
    ) -> int:
        """
        function strategyWithdrawalDelayBlocks(IStrategy strategy)
        external view returns (uint256);

        :param block_identifier:
        :return:
        """
        return await self.contract.functions.strategyWithdrawalDelayBlocks(strategy).call(
            block_identifier=block_number
        )


eigenpod_manager_contract = EigenPodManagerContract()
delegation_manager_contract = DelegationManagerContract()
