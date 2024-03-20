import json
import os
from functools import cached_property
from typing import cast

from eth_typing import HexStr
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.contract import AsyncContract
from web3.contract.contract import ContractEvent
from web3.types import BlockIdentifier, BlockNumber, ChecksumAddress, EventData

from src.common.clients import execution_client
from src.common.typings import RewardVoteInfo
from src.config.settings import settings

SECONDS_PER_MONTH: int = 2628000


class ContractWrapper:
    abi_path: str = ''
    settings_key: str = ''

    @property
    def events_blocks_range_interval(self) -> int:
        return 43200 // settings.network_config.SECONDS_PER_BLOCK  # 12 hrs

    @property
    def contract_address(self) -> ChecksumAddress:
        return getattr(settings.network_config, self.settings_key)

    @cached_property
    def contract(self) -> AsyncContract:
        current_dir = os.path.dirname(__file__)
        with open(os.path.join(current_dir, self.abi_path), encoding='utf-8') as f:
            abi = json.load(f)
        return execution_client.eth.contract(abi=abi, address=self.contract_address)

    def encode_abi(self, fn_name: str, args: list | None = None) -> HexStr:
        return self.contract.encodeABI(fn_name=fn_name, args=args)

    def __getattr__(self, item):
        return getattr(self.contract, item)

    async def _get_last_event(
        self,
        event: ContractEvent,
        from_block: BlockNumber,
        to_block: BlockNumber,
        argument_filters: dict | None = None,
    ) -> EventData | None:
        blocks_range = self.events_blocks_range_interval

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
        event: ContractEvent,
        from_block: BlockNumber,
        to_block: BlockNumber,
    ) -> list[EventData]:
        events: list[EventData] = []
        blocks_range = self.events_blocks_range_interval
        while to_block >= from_block:
            range_events = await event.get_logs(
                fromBlock=from_block,
                toBlock=BlockNumber(min(from_block + blocks_range, to_block)),
            )
            if range_events:
                events.extend(range_events)
            from_block = BlockNumber(from_block + blocks_range + 1)
        return events


class VaultContract(ContractWrapper):
    abi_path = 'abi/IEthVault.json'

    @property
    def contract_address(self) -> ChecksumAddress:
        return settings.vault

    async def get_validators_root(self) -> Bytes32:
        """Fetches vault's validators root."""
        return await self.contract.functions.validatorsRoot().call()

    async def get_validators_index(self) -> int:
        """Fetches vault's current validators index."""
        return await self.contract.functions.validatorIndex().call()

    async def get_registered_validators_public_keys(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[HexStr]:
        """Fetches the validator registered events."""
        events = await self._get_events(
            event=self.events.ValidatorRegistered, from_block=from_block, to_block=to_block
        )
        return [Web3.to_hex(event['args']['publicKey']) for event in events]

    async def mev_escrow(self) -> ChecksumAddress:
        return await self.contract.functions.mevEscrow().call()


class V2PoolContract(ContractWrapper):
    abi_path = 'abi/IV2Pool.json'
    settings_key = 'V2_POOL_CONTRACT_ADDRESS'

    async def get_registered_validators_public_keys(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[HexStr]:
        """Fetches the validator registered events."""
        events = await self._get_events(
            event=self.events.ValidatorRegistered, from_block=from_block, to_block=to_block
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
            self.events.ConfigUpdated,
            from_block=from_block or settings.network_config.KEEPER_GENESIS_BLOCK,
            to_block=to_block or await execution_client.eth.get_block_number(),
        )

    async def get_last_rewards_update(self) -> RewardVoteInfo | None:
        """Fetches the last rewards update."""
        last_event = await self._get_last_event(
            self.events.RewardsUpdated,
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

    async def get_exit_signatures_updated_event(self, vault: ChecksumAddress) -> EventData | None:
        from_block = settings.network_config.KEEPER_GENESIS_BLOCK
        to_block = await execution_client.eth.get_block_number()

        last_event = await self._get_last_event(
            self.events.ExitSignaturesUpdated,
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


class MulticallContract(ContractWrapper):
    abi_path = 'abi/Multicall.json'
    settings_key = 'MULTICALL_CONTRACT_ADDRESS'

    async def aggregate(
        self,
        data: list[tuple[ChecksumAddress, bool, HexStr]],
        block_number: BlockNumber | None = None,
    ) -> list:
        return await self.contract.functions.aggregate3(data).call(
            block_identifier=cast(BlockIdentifier, block_number)
        )


vault_contract = VaultContract()
validators_registry_contract = ValidatorsRegistryContract()
keeper_contract = KeeperContract()
v2_pool_contract = V2PoolContract()
v2_pool_escrow_contract = V2PoolEscrowContract()
multicall_contract = MulticallContract()
