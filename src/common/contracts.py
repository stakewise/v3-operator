import json
import os
from functools import cached_property
from typing import Callable

from sw_utils.decorators import retry_aiohttp_errors
from web3.contract import AsyncContract
from web3.types import BlockNumber, ChecksumAddress, EventData

from src.common.clients import execution_client
from src.config.settings import DEFAULT_RETRY_TIME, settings


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
        return execution_client.eth.contract(abi=abi, address=self.contract_address)  # type: ignore

    def __getattr__(self, item):
        return getattr(self.contract, item)

    async def _get_last_event(
        self, f: Callable, current_block: BlockNumber, from_block: BlockNumber
    ) -> EventData | None:
        @retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
        async def _retry_f(
            f: Callable, from_block: BlockNumber, to_block: BlockNumber
        ) -> list[EventData]:
            return await f(
                fromBlock=from_block,
                toBlock=to_block,
            )

        blocks_range = int(43200 / float(settings.network_config.SECONDS_PER_BLOCK))  # 12 hrs
        while current_block > from_block:
            events = await _retry_f(
                f,
                from_block=BlockNumber(max(current_block - blocks_range, from_block)),
                to_block=current_block,
            )
            if events:
                return events[-1]
            current_block = BlockNumber(current_block - blocks_range - 1)
        return None


class VaultContract(ContractWrapper):
    abi_path = 'abi/IEthVault.json'

    @property
    def contract_address(self) -> ChecksumAddress:
        return settings.vault


class ValidatorsRegistryContract(ContractWrapper):
    abi_path = 'abi/IValidatorsRegistry.json'
    settings_key = 'VALIDATORS_REGISTRY_CONTRACT_ADDRESS'


class KeeperContract(ContractWrapper):
    abi_path = 'abi/IKeeper.json'
    settings_key = 'KEEPER_CONTRACT_ADDRESS'

    async def get_config_updated_event(self) -> EventData | None:
        """Fetches the last oracles config updated event."""
        return await self._get_last_event(
            keeper_contract.events.ConfigUpdated.get_logs,
            current_block=await execution_client.eth.get_block_number(),
            from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        )

    async def get_reward_updated_event(self) -> EventData | None:
        """Fetches the last oracles config updated event."""
        return await self._get_last_event(
            keeper_contract.events.RewardsUpdated.get_logs,
            current_block=await execution_client.eth.get_block_number(),
            from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        )

    @retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
    async def get_rewards_min_oracles(self) -> int:
        """Fetches the last oracles config updated event."""
        return await self.contract.functions.rewardsMinOracles().call()

    @retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
    async def get_validators_min_oracles(self) -> int:
        """Fetches the last oracles config updated event."""
        return await self.contract.functions.validatorsMinOracles().call()


vault_contract = VaultContract()
validators_registry_contract = ValidatorsRegistryContract()
keeper_contract = KeeperContract()
