from collections import defaultdict
from queue import Queue

from eth_typing import BlockNumber, ChecksumAddress
from sw_utils import is_meta_vault_upgraded_to_release, memoize
from sw_utils.networks import META_VAULT_IDS, ContractReleaseVersion
from web3.types import Wei

from src.common.contracts import (
    MetaVaultContract,
    SubVaultsRegistryContract,
    V4MetaVaultContract,
    VaultContract,
)
from src.config.settings import settings
from src.meta_vault.typings import SubVaultRedemption


async def distribute_meta_vault_redemption_assets(
    vault_to_redemption_assets: dict[ChecksumAddress, Wei],
    block_number: BlockNumber | None = None,
) -> defaultdict[ChecksumAddress, Wei]:
    """
    Parameters:
    vault_to_redemption_assets: A mapping of vault addresses to their respective redemption assets,
    which may include meta vaults.

    Distribute redemption assets from meta vaults across their entire sub-vault tree.
    Returns a mapping of vault addresses to their respective redemption assets,
    including leaf vaults, root meta vaults, and all intermediary meta sub-vaults.
    """
    final_vault_to_redemption_assets: defaultdict[ChecksumAddress, Wei] = defaultdict(
        lambda: Wei(0)
    )

    queue: Queue[tuple[ChecksumAddress, Wei]] = Queue()
    for vault, assets in vault_to_redemption_assets.items():
        queue.put((vault, assets))

    while not queue.empty():
        vault, assets = queue.get()
        final_vault_to_redemption_assets[vault] = Wei(
            final_vault_to_redemption_assets[vault] + assets
        )
        if not await is_meta_vault(vault):
            continue
        sub_vaults_redemptions = await get_sub_vaults_redemptions(
            meta_vault_address=vault,
            assets_to_redeem=assets,
            block_number=block_number,
        )
        for sub_vault_redemption in sub_vaults_redemptions:
            queue.put((sub_vault_redemption.vault, sub_vault_redemption.assets))

    return final_vault_to_redemption_assets


async def get_sub_vaults_redemptions(
    meta_vault_address: ChecksumAddress,
    assets_to_redeem: Wei,
    block_number: BlockNumber | None = None,
) -> list[SubVaultRedemption]:
    """
    Distribute the specified assets to redeem from the meta vault across its
    direct sub-vaults only. Does not recurse into nested meta vaults.

    Returns a list of SubVaultRedemption entries, one per direct sub-vault.
    """
    meta_vault_contract = MetaVaultContract(meta_vault_address)
    sub_vaults_registry_address = await meta_vault_contract.sub_vaults_registry()
    sub_vaults_registry_contract = SubVaultsRegistryContract(sub_vaults_registry_address)

    sub_vaults_redemptions = await sub_vaults_registry_contract.calculate_sub_vaults_redemptions(
        assets_to_redeem, block_number=block_number
    )
    return sub_vaults_redemptions


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
