from web3.types import Wei

from src.common.contracts import os_token_vault_controller_contract


class OsTokenConverter:
    """
    Convert between shares and assets based on total assets and total shares.
    Helps to avoid repeating calls to the contract.
    """

    def __init__(self, total_assets: Wei, total_shares: Wei):
        self.total_assets = total_assets
        self.total_shares = total_shares

    def to_shares(self, assets: Wei) -> Wei:
        if self.total_assets == 0:
            return Wei(0)
        return Wei((assets * self.total_shares) // self.total_assets)

    def to_assets(self, shares: Wei) -> Wei:
        if self.total_shares == 0:
            return Wei(0)
        return Wei((shares * self.total_assets) // self.total_shares)


async def create_os_token_converter() -> OsTokenConverter:
    total_assets = await os_token_vault_controller_contract.functions.totalAssets().call()
    total_shares = await os_token_vault_controller_contract.functions.totalShares().call()
    return OsTokenConverter(total_assets=total_assets, total_shares=total_shares)
