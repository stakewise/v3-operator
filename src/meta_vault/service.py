from collections import defaultdict, deque

from eth_typing import BlockNumber, ChecksumAddress
from sw_utils import memoize
from sw_utils.networks import META_VAULT_IDS
from web3.types import Wei

from src.common.contracts import VaultContract
from src.meta_vault.contracts import MetaVaultContract, SubVaultsRegistryContract
from src.meta_vault.typings import SubVaultRedemption


async def distribute_meta_vault_redemption_assets(
    vault_to_redemption_assets: dict[ChecksumAddress, Wei],
    block_number: BlockNumber | None = None,
) -> dict[ChecksumAddress, Wei]:
    """
    Distribute redemption assets of meta vaults across their entire sub-vault tree.

    ``vault_to_redemption_assets`` maps vaults, possibly including meta vaults,
    to their redemption assets.

    Returns a mapping of vaults to redemption assets that contains leaf vaults,
    root meta vaults and all intermediary meta sub-vaults.
    """
    result: defaultdict[ChecksumAddress, Wei] = defaultdict(lambda: Wei(0))
    queue: deque[tuple[ChecksumAddress, Wei]] = deque(vault_to_redemption_assets.items())

    while queue:
        vault, assets = queue.popleft()
        result[vault] = Wei(result[vault] + assets)
        if assets <= 0 or not await is_meta_vault(vault):
            continue
        sub_vaults_redemptions = await get_sub_vaults_redemptions(
            meta_vault_address=vault,
            assets_to_redeem=assets,
            block_number=block_number,
        )
        for sub_vault_redemption in sub_vaults_redemptions:
            queue.append((sub_vault_redemption.vault, sub_vault_redemption.assets))

    return dict(result)


async def get_sub_vaults_redemptions(
    meta_vault_address: ChecksumAddress,
    assets_to_redeem: Wei,
    block_number: BlockNumber | None = None,
) -> list[SubVaultRedemption]:
    """
    Distribute the assets to redeem from the meta vault across its direct
    sub-vaults only. Does not recurse into nested meta vaults.
    """
    meta_vault_contract = MetaVaultContract(meta_vault_address)
    sub_vaults_registry_address = await meta_vault_contract.sub_vaults_registry()
    sub_vaults_registry_contract = SubVaultsRegistryContract(sub_vaults_registry_address)
    return await sub_vaults_registry_contract.calculate_sub_vaults_redemptions(
        assets_to_redeem, block_number=block_number
    )


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
