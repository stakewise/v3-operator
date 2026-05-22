from eth_typing import ChecksumAddress
from sw_utils import memoize
from sw_utils.networks import META_VAULT_IDS

from src.common.contracts import VaultContract


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
