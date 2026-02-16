import asyncio
import json
from functools import cached_property
from pathlib import Path
from typing import Callable, cast

from eth_typing import HexStr
from web3 import AsyncWeb3, Web3
from web3.contract import AsyncContract
from web3.contract.async_contract import (
    AsyncContractEvent,
    AsyncContractEvents,
    AsyncContractFunctions,
)
from web3.types import BlockNumber, ChecksumAddress, EventData, Wei

from src.common.clients import execution_client as default_execution_client
from src.common.execution import transaction_gas_wrapper
from src.common.typings import (
    ExitQueueMissingAssetsParams,
    HarvestParams,
    RewardVoteInfo,
)
from src.config.networks import ZERO_CHECKSUM_ADDRESS
from src.config.settings import (
    EVENTS_CONCURRENCY_CHUNK,
    EVENTS_CONCURRENCY_LIMIT,
    settings,
)
from src.meta_vault.typings import SubVaultExitRequest
from src.validators.typings import V2ValidatorEventData
from src.withdrawals.typings import WithdrawalEvent

SOLIDITY_UINT256_MAX = 2**256 - 1


class ContractWrapper:
    abi_path: str = ''
    settings_key: str = ''

    def __init__(
        self, address: ChecksumAddress | None = None, execution_client: AsyncWeb3 | None = None
    ):
        self.address = address
        self.execution_client = execution_client or default_execution_client

    @property
    def contract_address(self) -> ChecksumAddress:
        return self.address or getattr(settings.network_config, self.settings_key)

    @cached_property
    def contract(self) -> AsyncContract:
        current_dir = Path(__file__).parent
        with open(current_dir / self.abi_path, encoding='utf-8') as f:
            abi = json.load(f)
        return self.execution_client.eth.contract(abi=abi, address=self.contract_address)

    @property
    def functions(self) -> AsyncContractFunctions:
        return self.contract.functions

    @property
    def events(self) -> AsyncContractEvents:
        return self.contract.events

    def encode_abi(self, fn_name: str, args: list | None = None) -> HexStr:
        return self.contract.encode_abi(fn_name, args=args)

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
                from_block=BlockNumber(max(to_block - blocks_range, from_block)),
                to_block=to_block,
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
                from_block=from_block,
                to_block=BlockNumber(min(from_block + blocks_range, to_block)),
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


class BaseEncoder:
    """Base class for contract ABI encoders."""

    contract_class: type[ContractWrapper]

    def __init__(self) -> None:
        # Use dummy address since we only need to encode ABI calls, no actual contract interaction
        self.contract = self.contract_class(address=ZERO_CHECKSUM_ADDRESS)


class VaultContract(ContractWrapper, VaultStateMixin):
    abi_path = 'abi/IEthVault.json'

    async def get_registered_validators_public_keys(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[HexStr]:
        """Fetches the validator registered events."""
        v1_validators_from_block = max(
            from_block, settings.network_config.KEEPER_GENESIS_BLOCK, settings.vault_first_block
        )
        v2_validators_from_block = max(
            from_block, settings.network_config.PECTRA_BLOCK, settings.vault_first_block
        )
        semaphore = asyncio.BoundedSemaphore(EVENTS_CONCURRENCY_LIMIT)
        pending = set()
        for block_number in range(v1_validators_from_block, to_block + 1, EVENTS_CONCURRENCY_CHUNK):
            task = asyncio.create_task(
                self._get_public_keys_chunk(
                    event=self.events.ValidatorRegistered,  # type: ignore
                    from_block=BlockNumber(block_number),
                    to_block=BlockNumber(
                        min(block_number + EVENTS_CONCURRENCY_CHUNK - 1, to_block)
                    ),
                    semaphore=semaphore,
                )
            )
            pending.add(task)

        for block_number in range(v2_validators_from_block, to_block + 1, EVENTS_CONCURRENCY_CHUNK):
            task = asyncio.create_task(
                self._get_public_keys_chunk(
                    event=self.events.V2ValidatorRegistered,  # type: ignore
                    from_block=BlockNumber(block_number),
                    to_block=BlockNumber(
                        min(block_number + EVENTS_CONCURRENCY_CHUNK - 1, to_block)
                    ),
                    semaphore=semaphore,
                )
            )
            pending.add(task)

        keys: list[HexStr] = []
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                keys.extend(task.result())

        return keys

    async def get_funding_events(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[V2ValidatorEventData]:
        events = await self._get_events(
            event=self.events.ValidatorFunded,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )
        return [
            V2ValidatorEventData(
                public_key=Web3.to_hex(event['args']['publicKey']),
                amount=Wei(event['args']['amount']),
            )
            for event in events
        ]

    async def mev_escrow(self) -> ChecksumAddress:
        return await self.contract.functions.mevEscrow().call()

    async def version(self) -> int:
        return await self.contract.functions.version().call()

    async def validators_manager(self) -> ChecksumAddress:
        return await self.contract.functions.validatorsManager().call()

    async def get_exit_queue_index(self, position_ticket: int) -> int:
        return await self.contract.functions.getExitQueueIndex(position_ticket).call()

    async def get_validator_withdrawal_submitted_events(
        self,
        from_block: BlockNumber,
    ) -> list[WithdrawalEvent]:
        from_block = max(from_block, settings.network_config.KEEPER_GENESIS_BLOCK)
        if settings.network_config.PECTRA_BLOCK:
            from_block = max(from_block, settings.network_config.PECTRA_BLOCK)
        events = await self._get_events(
            self.events.ValidatorWithdrawalSubmitted,  # type: ignore
            from_block=from_block,
            to_block=await self.execution_client.eth.get_block_number(),
        )
        return [
            WithdrawalEvent(
                public_key=Web3.to_hex(event['args']['publicKey']),
                amount=event['args']['amount'],
                block_number=BlockNumber(event['blockNumber']),
            )
            for event in events
        ]

    async def _get_public_keys_chunk(
        self,
        event: type[AsyncContractEvent],
        from_block: BlockNumber,
        to_block: BlockNumber,
        semaphore: asyncio.BoundedSemaphore,
    ) -> list[HexStr]:
        async with semaphore:
            events = await self._get_events(
                event=event,
                from_block=from_block,
                to_block=to_block,
            )
            return [Web3.to_hex(event['args']['publicKey']) for event in events]


class Erc20Contract(ContractWrapper):
    abi_path = 'abi/Erc20Token.json'

    async def get_balance(
        self, address: ChecksumAddress, block_number: BlockNumber | None = None
    ) -> Wei:
        return await self.contract.functions.balanceOf(address).call(block_identifier=block_number)


class VaultEncoder(BaseEncoder):
    """Helper class to encode Vault contract ABI calls."""

    contract_class = VaultContract

    def update_state(self, harvest_params: HarvestParams) -> HexStr:
        return self.contract.encode_abi(
            fn_name='updateState',
            args=[
                (
                    harvest_params.rewards_root,
                    harvest_params.reward,
                    harvest_params.unlocked_mev_reward,
                    harvest_params.proof,
                ),
            ],
        )


class ValidatorsRegistryContract(ContractWrapper):
    abi_path = 'abi/IValidatorsRegistry.json'
    settings_key = 'VALIDATORS_REGISTRY_CONTRACT_ADDRESS'

    async def get_registry_root(self) -> HexStr:
        """Fetches the latest validators registry root."""
        deposit_root = await self.contract.functions.get_deposit_root().call()
        return Web3.to_hex(deposit_root)


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
            to_block=to_block or await self.execution_client.eth.get_block_number(),
        )

    async def get_last_rewards_update(
        self, block_number: BlockNumber | None = None
    ) -> RewardVoteInfo | None:
        """Fetches the last rewards update."""
        to_block = block_number or await self.execution_client.eth.get_block_number()
        last_event = await self._get_last_event(
            self.events.RewardsUpdated,  # type: ignore
            from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
            to_block=to_block,
        )
        if not last_event:
            return None

        voting_info = RewardVoteInfo(
            ipfs_hash=last_event['args']['rewardsIpfsHash'],
            rewards_root=last_event['args']['rewardsRoot'],
        )
        return voting_info

    async def get_last_rewards_updated_event(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> EventData | None:
        return await self._get_last_event(
            cast(type[AsyncContractEvent], self.contract.events.RewardsUpdated),
            from_block=from_block,
            to_block=to_block,
        )

    async def get_exit_signatures_updated_event(
        self,
        vault: ChecksumAddress,
        from_block: BlockNumber | None = None,
        to_block: BlockNumber | None = None,
    ) -> EventData | None:
        from_block = from_block or settings.network_config.KEEPER_GENESIS_BLOCK
        to_block = to_block or await self.execution_client.eth.get_block_number()

        last_event = await self._get_last_event(
            self.events.ExitSignaturesUpdated,  # type: ignore
            from_block=from_block,
            to_block=to_block,
            argument_filters={'vault': vault},
        )

        return last_event

    async def can_harvest(
        self, vault_address: ChecksumAddress, block_number: BlockNumber | None = None
    ) -> bool:
        return await self.contract.functions.canHarvest(vault_address).call(
            block_identifier=block_number
        )


class OsTokenVaultControllerContract(ContractWrapper):
    abi_path = 'abi/IOsTokenVaultController.json'
    settings_key = 'OS_TOKEN_VAULT_CONTROLLER_CONTRACT_ADDRESS'

    async def total_assets(self, block_number: BlockNumber | None = None) -> Wei:
        return await self.contract.functions.totalAssets().call(block_identifier=block_number)

    async def total_shares(self, block_number: BlockNumber | None = None) -> Wei:
        return await self.contract.functions.totalShares().call(block_identifier=block_number)


class RewardSplitterContract(ContractWrapper):
    abi_path = 'abi/IRewardSplitter.json'


class RewardSplitterEncoder(BaseEncoder):
    """
    Helper class to encode RewardSplitter contract ABI calls
    """

    contract_class = RewardSplitterContract

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


class MetaVaultContract(ContractWrapper):
    abi_path = 'abi/IEthMetaVault.json'

    def __init__(
        self, address: ChecksumAddress | None = None, execution_client: AsyncWeb3 | None = None
    ):
        super().__init__(address, execution_client)
        self._sub_vaults_registry: ChecksumAddress | None = None

    async def sub_vaults_registry(self) -> ChecksumAddress:
        if self._sub_vaults_registry is None:
            self._sub_vaults_registry = await self.contract.functions.subVaultsRegistry().call()
        return self._sub_vaults_registry

    async def withdrawable_assets(self) -> Wei:
        return await self.contract.functions.withdrawableAssets().call()

    async def get_exit_queue_index(self, position_ticket: int) -> int:
        return await self.contract.functions.getExitQueueIndex(position_ticket).call()


class MetaVaultEncoder(BaseEncoder):
    """Helper class to encode MetaVault contract ABI calls."""

    contract_class = MetaVaultContract

    def update_state(self, harvest_params: HarvestParams) -> HexStr:
        return self.contract.encode_abi(
            fn_name='updateState',
            args=[
                (
                    harvest_params.rewards_root,
                    harvest_params.reward,
                    harvest_params.unlocked_mev_reward,
                    harvest_params.proof,
                ),
            ],
        )


class SubVaultsRegistryContract(ContractWrapper):
    abi_path = 'abi/ISubVaultsRegistry.json'

    async def get_last_rewards_nonce_updated_event(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> EventData | None:
        """
        Returns the latest RewardsNonceUpdated event data from the contract.
        """
        event = await self._get_last_event(
            event=cast(type[AsyncContractEvent], self.contract.events.RewardsNonceUpdated),
            from_block=from_block,
            to_block=to_block,
        )
        return event

    async def deposit_to_sub_vaults(self) -> HexStr:
        tx_function = self.contract.functions.depositToSubVaults()
        tx_hash = await transaction_gas_wrapper(tx_function)
        return Web3.to_hex(tx_hash)


class SubVaultsRegistryEncoder(BaseEncoder):
    """Helper class to encode SubVaultsRegistry contract ABI calls."""

    contract_class = SubVaultsRegistryContract

    def claim_sub_vaults_exited_assets(
        self, sub_vault_exit_requests: list[SubVaultExitRequest]
    ) -> HexStr:
        exit_requests_arg: list[tuple] = []

        for request in sub_vault_exit_requests:
            exit_requests_arg.append(
                (
                    request.exit_queue_index,
                    request.vault,
                    request.timestamp,
                )
            )
        return self.contract.encode_abi(
            fn_name='claimSubVaultsExitedAssets', args=[exit_requests_arg]
        )


class MulticallContract(ContractWrapper):
    abi_path = 'abi/Multicall.json'
    settings_key = 'MULTICALL_CONTRACT_ADDRESS'

    async def aggregate(
        self,
        data: list[tuple[ChecksumAddress, HexStr]],
        block_number: BlockNumber | None = None,
    ) -> tuple[BlockNumber, list]:
        return await self.contract.functions.aggregate(data).call(block_identifier=block_number)

    async def tx_aggregate(
        self,
        data: list[tuple[ChecksumAddress, HexStr]],
    ) -> HexStr:
        tx_function = self.contract.functions.aggregate(data)
        tx_hash = await transaction_gas_wrapper(tx_function)
        return Web3.to_hex(tx_hash)


class OsTokenRedeemerContract(ContractWrapper):
    abi_path = 'abi/IOsTokenRedeemer.json'
    settings_key = 'OS_TOKEN_REDEEMER_CONTRACT_ADDRESS'

    async def nonce(self) -> int:
        return await self.contract.functions.nonce().call()


class ValidatorsCheckerContract(ContractWrapper):
    abi_path = 'abi/IValidatorsChecker.json'
    settings_key = 'VALIDATORS_CHECKER_CONTRACT_ADDRESS'

    async def multicall(
        self,
        calls: list[HexStr],
        block_number: BlockNumber | None = None,
    ) -> list[bytes]:
        return await self.contract.functions.multicall(calls).call(block_identifier=block_number)

    async def get_exit_queue_cumulative_tickets(
        self,
        vault_address: ChecksumAddress,
        harvest_params: HarvestParams | None,
        block_number: BlockNumber,
    ) -> int:
        calls = []
        if harvest_params is not None:
            calls.append(
                self._get_update_vault_state_call(
                    vault=vault_address,
                    harvest_params=harvest_params,
                )
            )

        calls.append(self.encode_abi('getExitQueueCumulativeTickets', args=[vault_address]))
        response = await self.multicall(calls=calls, block_number=block_number)
        return Web3.to_int(response[-1])

    async def get_exit_queue_missing_assets(
        self,
        exit_queue_missing_assets_params: ExitQueueMissingAssetsParams,
        harvest_params: HarvestParams | None,
        block_number: BlockNumber,
    ) -> Wei:
        calls: list[HexStr] = []
        vault = exit_queue_missing_assets_params.vault

        if harvest_params is not None:
            calls.append(
                self._get_update_vault_state_call(
                    vault=vault,
                    harvest_params=harvest_params,
                )
            )

        calls.append(self._get_exit_queue_missing_assets_call(exit_queue_missing_assets_params))
        multicall_response = await self.contract.functions.multicall(calls).call(
            block_identifier=block_number
        )

        return Wei(Web3.to_int(multicall_response[-1]))

    def _get_update_vault_state_call(
        self, vault: ChecksumAddress, harvest_params: HarvestParams
    ) -> HexStr:
        return self.encode_abi(
            'updateVaultState',
            [
                vault,
                (
                    harvest_params.rewards_root,
                    harvest_params.reward,
                    harvest_params.unlocked_mev_reward,
                    harvest_params.proof,
                ),
            ],
        )

    def _get_exit_queue_missing_assets_call(self, params: ExitQueueMissingAssetsParams) -> HexStr:
        return self.encode_abi(
            'getExitQueueMissingAssets',
            [
                params.vault,
                params.withdrawing_assets,
                params.exit_queue_cumulative_ticket,
            ],
        )


validators_registry_contract = ValidatorsRegistryContract()
keeper_contract = KeeperContract()
multicall_contract = MulticallContract()
validators_checker_contract = ValidatorsCheckerContract()
os_token_vault_controller_contract = OsTokenVaultControllerContract()
os_token_redeemer_contract = OsTokenRedeemerContract()
