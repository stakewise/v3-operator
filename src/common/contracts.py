import functools
import json
import os
from functools import cached_property
from typing import Callable

from eth_typing import HexStr
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.contract import AsyncContract
from web3.contract.async_contract import (
    AsyncContractEvent,
    AsyncContractEvents,
    AsyncContractFunctions,
)
from web3.types import BlockNumber, ChecksumAddress, EventData

from src.common.clients import execution_client
from src.common.typings import HarvestParams, RewardVoteInfo
from src.config.settings import settings

SECONDS_PER_MONTH: int = 2628000


class ContractWrapper:
    abi_path: str = ''
    settings_key: str = ''

    @property
    def contract_address(self) -> ChecksumAddress:
        return getattr(settings.network_config, self.settings_key)

    @cached_property
    def contract(self) -> AsyncContract:
        current_dir = os.path.dirname(__file__)
        with open(os.path.join(current_dir, self.abi_path), encoding='utf-8') as f:
            abi = json.load(f)
        return execution_client.eth.contract(abi=abi, address=self.contract_address)

    @property
    def address(self) -> ChecksumAddress:
        return self.contract.address

    @property
    def functions(self) -> AsyncContractFunctions:
        return self.contract.functions

    @property
    def events(self) -> AsyncContractEvents:
        return self.contract.events

    def encode_abi(self, fn_name: str, args: list | None = None) -> HexStr:
        return self.contract.encodeABI(fn_name=fn_name, args=args)

    async def _get_last_event(
        self,
        event: type[AsyncContractEvent],
        from_block: BlockNumber,
        to_block: BlockNumber,
        argument_filters: dict | None = None,
    ) -> EventData | None:
        blocks_range = settings.events_blocks_range_interval
        while to_block >= from_block:
            events = await event.get_logs(
                fromBlock=BlockNumber(max(to_block - blocks_range, from_block)),
                toBlock=to_block,
                argument_filters=argument_filters,
            )
            if events:
                return events[-1]
            to_block = BlockNumber(to_block - blocks_range - 1)
        return None

    async def _get_events(
        self,
        event: type[AsyncContractEvent],
        from_block: BlockNumber,
        to_block: BlockNumber,
    ) -> list[EventData]:
        events: list[EventData] = []
        blocks_range = settings.events_blocks_range_interval
        while to_block >= from_block:
            range_events = await event.get_logs(
                fromBlock=from_block,
                toBlock=BlockNumber(min(from_block + blocks_range, to_block)),
            )
            if range_events:
                events.extend(range_events)
            from_block = BlockNumber(from_block + blocks_range + 1)
        return events


class VaultStateMixin:
    encode_abi: Callable

    def get_update_state_call(self, harvest_params: HarvestParams) -> HexStr:
        update_state_call = self.encode_abi(
            fn_name='updateState',
            args=[
                (
                    harvest_params.rewards_root,
                    harvest_params.reward,
                    harvest_params.unlocked_mev_reward,
                    harvest_params.proof,
                )
            ],
        )
        return update_state_call


class VaultV1Contract(ContractWrapper, VaultStateMixin):
    abi_path = 'abi/IEthVaultV1.json'

    @property
    def contract_address(self) -> ChecksumAddress:
        return settings.vault

    async def get_validators_root(self) -> Bytes32:
        """Fetches vault's validators root."""
        return await self.contract.functions.validatorsRoot().call()

    async def get_validators_index(self) -> int:
        """Fetches vault's current validators index."""
        return await self.contract.functions.validatorIndex().call()


class VaultContract(ContractWrapper, VaultStateMixin):
    abi_path = 'abi/IEthVault.json'

    @property
    def contract_address(self) -> ChecksumAddress:
        return settings.vault

    async def get_registered_validators_public_keys(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[HexStr]:
        """Fetches the validator registered events."""
        events = await self._get_events(
            event=self.events.ValidatorRegistered,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )
        return [Web3.to_hex(event['args']['publicKey']) for event in events]

    async def mev_escrow(self) -> ChecksumAddress:
        return await self.contract.functions.mevEscrow().call()

    async def version(self) -> int:
        return await self.contract.functions.version().call()

    async def validators_manager(self) -> ChecksumAddress:
        return await self.contract.functions.validatorsManager().call()


class GnoVaultContract(ContractWrapper, VaultStateMixin):
    abi_path = 'abi/IGnoVault.json'

    @property
    def contract_address(self) -> ChecksumAddress:
        return settings.vault

    def get_swap_xdai_call(self) -> HexStr:
        return self.encode_abi(fn_name='swapXdaiToGno', args=[])


class V2PoolContract(ContractWrapper):
    abi_path = 'abi/IV2Pool.json'
    settings_key = 'V2_POOL_CONTRACT_ADDRESS'

    async def get_registered_validators_public_keys(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[HexStr]:
        """Fetches the validator registered events."""
        events = await self._get_events(
            event=self.events.ValidatorRegistered,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )
        return [Web3.to_hex(event['args']['publicKey']) for event in events]


class V2PoolEscrowContract(ContractWrapper):
    abi_path = 'abi/IV2PoolEscrow.json'
    settings_key = 'V2_POOL_ESCROW_CONTRACT_ADDRESS'

    async def get_owner(self) -> ChecksumAddress:
        """Fetches the owner of the contract."""
        return await self.contract.functions.owner().call()


class ValidatorsRegistryContract(ContractWrapper):
    abi_path = 'abi/IValidatorsRegistry.json'
    settings_key = 'VALIDATORS_REGISTRY_CONTRACT_ADDRESS'

    async def get_registry_root(self) -> Bytes32:
        """Fetches the latest validators registry root."""
        return await self.contract.functions.get_deposit_root().call()


class KeeperContract(ContractWrapper):
    abi_path = 'abi/IKeeper.json'
    settings_key = 'KEEPER_CONTRACT_ADDRESS'

    async def get_config_updated_event(
        self, from_block: BlockNumber | None = None, to_block: BlockNumber | None = None
    ) -> EventData | None:
        """Fetches the last oracles config updated event."""
        return await self._get_last_event(
            self.events.ConfigUpdated,  # type: ignore
            from_block=from_block or settings.network_config.KEEPER_GENESIS_BLOCK,
            to_block=to_block or await execution_client.eth.get_block_number(),
        )

    async def get_last_rewards_update(self) -> RewardVoteInfo | None:
        """Fetches the last rewards update."""
        last_event = await self._get_last_event(
            self.events.RewardsUpdated,  # type: ignore
            from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
            to_block=await execution_client.eth.get_block_number(),
        )
        if not last_event:
            return None

        voting_info = RewardVoteInfo(
            ipfs_hash=last_event['args']['rewardsIpfsHash'],
            rewards_root=last_event['args']['rewardsRoot'],
        )
        return voting_info

    async def get_exit_signatures_updated_event(
        self,
        vault: ChecksumAddress,
        from_block: BlockNumber | None = None,
        to_block: BlockNumber | None = None,
    ) -> EventData | None:
        from_block = from_block or settings.network_config.KEEPER_GENESIS_BLOCK
        to_block = to_block or await execution_client.eth.get_block_number()

        last_event = await self._get_last_event(
            self.events.ExitSignaturesUpdated,  # type: ignore
            from_block=from_block,
            to_block=to_block,
            argument_filters={'vault': vault},
        )

        return last_event

    async def get_rewards_min_oracles(self) -> int:
        """Fetches the last oracles config updated event."""
        return await self.contract.functions.rewardsMinOracles().call()

    async def get_validators_min_oracles(self) -> int:
        """Fetches the last oracles config updated event."""
        return await self.contract.functions.validatorsMinOracles().call()

    async def can_harvest(self, vault_address: ChecksumAddress) -> bool:
        return await self.contract.functions.canHarvest(vault_address).call()


class DepositDataRegistryContract(ContractWrapper):
    abi_path = 'abi/IDepositDataRegistry.json'
    settings_key = 'DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS'

    async def get_deposit_data_manager(self) -> ChecksumAddress:
        """Fetches the vault deposit data manager address."""
        return await self.contract.functions.getDepositDataManager(settings.vault).call()

    async def get_validators_root(self) -> Bytes32:
        """Fetches vault's validators root."""
        return await self.contract.functions.depositDataRoots(settings.vault).call()

    async def get_validators_index(self) -> int:
        """Fetches vault's current validators index."""
        return await self.contract.functions.depositDataIndexes(settings.vault).call()


class MulticallContract(ContractWrapper):
    abi_path = 'abi/Multicall.json'
    settings_key = 'MULTICALL_CONTRACT_ADDRESS'

    async def aggregate(
        self,
        data: list[tuple[ChecksumAddress, HexStr]],
        block_number: BlockNumber | None = None,
    ) -> tuple[BlockNumber, list]:
        return await self.contract.functions.aggregate(data).call(block_identifier=block_number)


@functools.cache
def get_gno_vault_contract() -> GnoVaultContract:
    return GnoVaultContract()


vault_contract = VaultContract()
vault_v1_contract = VaultV1Contract()
validators_registry_contract = ValidatorsRegistryContract()
keeper_contract = KeeperContract()
v2_pool_contract = V2PoolContract()
v2_pool_escrow_contract = V2PoolEscrowContract()
multicall_contract = MulticallContract()
deposit_data_registry_contract = DepositDataRegistryContract()
