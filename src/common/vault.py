import logging

from hexbytes import HexBytes
from sw_utils.typings import Bytes32
from web3.types import TxParams

from src.common.contracts import (
    deposit_data_registry_contract,
    vault_contract,
    vault_v1_contract,
)
from src.common.typings import HarvestParams
from src.config.settings import settings

logger = logging.getLogger(__name__)


class Vault:
    async def version(self):
        return await vault_contract.version()

    async def get_validators_root(self) -> Bytes32:
        """Fetches vault's validators root."""
        if await self.version() == 1:
            return await vault_v1_contract.get_validators_root()
        return await deposit_data_registry_contract.get_validators_root()

    async def get_validators_index(self) -> int:
        """Fetches vault's current validators index."""
        if await self.version() == 1:
            return await vault_v1_contract.get_validators_index()
        return await deposit_data_registry_contract.get_validators_index()

    async def register_single_validator(
        self,
        register_call_args: list,
        tx_params: TxParams,
        harvest_params: HarvestParams | None,
        register_via_vault_v2: bool = False,
    ) -> HexBytes:
        version = await self.version()

        if version == 1:
            return await self._vault_register_single(
                register_call_args,
                tx_params,
                harvest_params,
            )

        if register_via_vault_v2:
            return await self._vault_register_multiple(
                register_call_args,
                tx_params,
                harvest_params,
            )

        return await self._deposit_registry_register_single(
            register_call_args,
            tx_params,
            harvest_params,
        )

    async def register_multiple_validators(
        self,
        register_call_args: list,
        tx_params: TxParams,
        harvest_params: HarvestParams | None,
        register_via_vault_v2: bool = False,
    ) -> HexBytes:
        version = await self.version()

        if version == 1 or register_via_vault_v2:
            return await self._vault_register_multiple(
                register_call_args,
                tx_params,
                harvest_params,
            )
        return await self._deposit_registry_register_multiple(
            register_call_args,
            tx_params,
            harvest_params,
        )

    async def _vault_register_single(
        self, register_call_args: list, tx_params: TxParams, harvest_params: HarvestParams | None
    ) -> HexBytes:
        if harvest_params is not None:
            update_state_call = vault_contract.encode_abi(
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
            register_call = vault_contract.encode_abi(
                fn_name='registerValidator',
                args=register_call_args,
            )
            tx = await vault_contract.functions.multicall(
                [update_state_call, register_call]
            ).transact(tx_params)
        else:
            register_func = vault_contract.functions.registerValidator
            tx = await register_func(*register_call_args).transact(tx_params)
        return tx

    async def _deposit_registry_register_single(
        self, register_call_args: list, tx_params: TxParams, harvest_params: HarvestParams | None
    ) -> HexBytes:
        register_call_args.insert(0, settings.vault)
        if harvest_params is not None:
            update_state_call = deposit_data_registry_contract.encode_abi(
                fn_name='updateVaultState',
                args=[
                    settings.vault,
                    (
                        harvest_params.rewards_root,
                        harvest_params.reward,
                        harvest_params.unlocked_mev_reward,
                        harvest_params.proof,
                    ),
                ],
            )
            register_call = deposit_data_registry_contract.encode_abi(
                fn_name='registerValidator',
                args=register_call_args,
            )
            tx = await deposit_data_registry_contract.functions.multicall(
                [update_state_call, register_call]
            ).transact(tx_params)
        else:
            register_func = deposit_data_registry_contract.functions.registerValidator
            tx = await register_func(*register_call_args).transact(tx_params)
        return tx

    async def _vault_register_multiple(
        self, register_call_args: list, tx_params: TxParams, harvest_params: HarvestParams | None
    ) -> HexBytes:
        if harvest_params is not None:
            update_state_call = vault_contract.encode_abi(
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
            register_call = vault_contract.encode_abi(
                fn_name='registerValidators',
                args=register_call_args,
            )
            tx = await vault_contract.functions.multicall(
                [update_state_call, register_call]
            ).transact(tx_params)
        else:
            register_func = vault_contract.functions.registerValidators
            tx = await register_func(*register_call_args).transact(tx_params)
        return tx

    async def _deposit_registry_register_multiple(
        self, register_call_args: list, tx_params: TxParams, harvest_params: HarvestParams | None
    ) -> HexBytes:
        if harvest_params is not None:
            update_state_call = deposit_data_registry_contract.encode_abi(
                fn_name='updateVaultState',
                args=[
                    settings.vault,
                    (
                        harvest_params.rewards_root,
                        harvest_params.reward,
                        harvest_params.unlocked_mev_reward,
                        harvest_params.proof,
                    ),
                ],
            )
            register_call = deposit_data_registry_contract.encode_abi(
                fn_name='registerValidators',
                args=register_call_args,
            )
            tx = await deposit_data_registry_contract.functions.multicall(
                [update_state_call, register_call]
            ).transact(tx_params)
        else:
            register_func = deposit_data_registry_contract.functions.registerValidators
            tx = await register_func(*register_call_args).transact(tx_params)
        return tx
