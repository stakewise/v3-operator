from collections import defaultdict
from typing import cast

from eth_typing import ChecksumAddress
from web3.types import Wei

from src.common.contracts import VaultContract
from src.common.decorators import memoize
from src.config.settings import settings
from src.common.contracts import MetaVaultContract


@memoize
async def is_meta_vault(vault_address: ChecksumAddress) -> bool:
    """
    Checks if the given vault is a meta vault by comparing its vault ID
    with the predefined META_VAULT_ID.

    Currently, meta vaults are not included in the vaults table.
    Since adding a new field to the vaults table is not feasible,
    memoization is used to minimize the number of EL calls.
    """
    vault_contract = VaultContract(vault_address)
    vault_id = await vault_contract.vault_id()
    return vault_id == settings.network_config.META_VAULT_ID


async def distribute_meta_vault_redemption_assets(
    vault_to_redemption_assets: defaultdict[ChecksumAddress, Wei],
) -> defaultdict[ChecksumAddress, Wei]:
    """
    Parameters:
    vault_to_redemption_assets: A mapping of vault addresses to their respective redemption assets,
    which may include meta vaults.

    Distribute redemption assets from meta vaults to their underlying sub-vaults.
    Returns a mapping of vault addresses to their respective redemption assets,
    ensuring all assets are assigned to non-meta vaults.
    """
    final_vault_to_redemption_assets: defaultdict[ChecksumAddress, int] = defaultdict(lambda: 0)

    for vault, assets in vault_to_redemption_assets.items():
        if await is_meta_vault(vault):
            sub_vaults_redemptions = await get_meta_vault_redemption_assets(
                meta_vault_address=vault,
                assets_to_redeem=assets,
            )
            for sub_vault, sub_assets in sub_vaults_redemptions.items():
                final_vault_to_redemption_assets[sub_vault] += sub_assets
        else:
            final_vault_to_redemption_assets[vault] += assets

    return cast(defaultdict[ChecksumAddress, Wei], final_vault_to_redemption_assets)


async def get_meta_vault_redemption_assets(
    meta_vault_address: ChecksumAddress,
    assets_to_redeem: Wei,
) -> defaultdict[ChecksumAddress, Wei]:
    """
    This function distributes the specified assets to redeem from the meta vault
    among its underlying sub-vaults. It handles both regular and nested meta vaults.
    Finally every asset should be assigned to a non-meta vault.

    Returns a mapping of vault addresses to their respective redemption assets.
    """
    vault_to_redemption_assets: defaultdict[ChecksumAddress, int] = defaultdict(lambda: 0)
    meta_vault_contract = MetaVaultContract(meta_vault_address)

    sub_vaults_redemptions = await meta_vault_contract.calculate_sub_vaults_redemptions(
        assets_to_redeem
    )

    for sub_vault_redemption in sub_vaults_redemptions:
        if await is_meta_vault(sub_vault_redemption.vault):
            sub_vault_assets = await get_meta_vault_redemption_assets(
                sub_vault_redemption.vault,
                sub_vault_redemption.assets,
            )
            for vault, assets in sub_vault_assets.items():
                vault_to_redemption_assets[vault] += assets
        else:
            vault_to_redemption_assets[sub_vault_redemption.vault] += sub_vault_redemption.assets

    return cast(defaultdict[ChecksumAddress, Wei], vault_to_redemption_assets)
