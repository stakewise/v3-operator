from eth_typing import HexStr
from web3 import AsyncWeb3, Web3
from web3.types import ChecksumAddress, Wei

from src.common.contracts import BaseEncoder, ContractWrapper
from src.common.execution import transaction_gas_wrapper
from src.common.typings import HarvestParams
from src.meta_vault.typings import SubVaultExitRequest


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
