from sw_utils import OsTokenConverter
from web3.types import BlockNumber

from src.common.contracts import os_token_vault_controller_contract


async def create_os_token_converter(block_number: BlockNumber | None = None) -> OsTokenConverter:
    total_assets = await os_token_vault_controller_contract.total_assets(block_number)
    total_shares = await os_token_vault_controller_contract.total_shares(block_number)
    return OsTokenConverter(total_assets=total_assets, total_shares=total_shares)
