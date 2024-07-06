import logging

from sw_utils.typings import Bytes32

from src.common.contracts import (
    deposit_data_registry_contract,
    vault_contract,
    vault_v1_contract,
)

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
