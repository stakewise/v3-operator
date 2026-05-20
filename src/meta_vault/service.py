from eth_typing import ChecksumAddress
from sw_utils import is_meta_vault_upgraded_to_release, memoize
from sw_utils.networks import META_VAULT_IDS, ContractReleaseVersion

from src.common.contracts import (
    MetaVaultContract,
    SubVaultsRegistryContract,
    V4MetaVaultContract,
    VaultContract,
)
from src.config.settings import settings


@memoize
async def is_meta_vault(vault_address: ChecksumAddress) -> bool:
    """
    Checks if the given vault is a meta vault by comparing its vault ID
    with the predefined META_VAULT_IDS.

    Memoization is used to minimize the number of EL calls.
    """
    vault_contract = VaultContract(vault_address)
    vault_id = await vault_contract.vault_id()
    return vault_id in META_VAULT_IDS


async def is_meta_vault_state_update_required(meta_vault_address: ChecksumAddress) -> bool:
    vault_version = await VaultContract(meta_vault_address).version()

    if is_meta_vault_upgraded_to_release(
        settings.network, meta_vault_address, vault_version, ContractReleaseVersion.V5
    ):
        # V5 release: canUpdateState moved to SubVaultsRegistry
        meta_vault_contract = MetaVaultContract(meta_vault_address)
        sub_vaults_registry_address = await meta_vault_contract.sub_vaults_registry()
        sub_vaults_registry_contract = SubVaultsRegistryContract(sub_vaults_registry_address)
        return await sub_vaults_registry_contract.is_state_update_required()

    # V4 release: canUpdateState is on the vault contract directly
    v4_meta_vault_contract = V4MetaVaultContract(meta_vault_address)
    return await v4_meta_vault_contract.is_state_update_required()
