import pytest
from web3.types import Wei

from src.redemptions.os_token_converter import OsTokenConverter


class TestOsTokenConverter:
    @pytest.mark.parametrize(
        'total_assets,total_shares,assets,expected_shares',
        [
            (Wei(1000), Wei(100), Wei(500), Wei(50)),
            (Wei(2000), Wei(200), Wei(1000), Wei(100)),
            (Wei(0), Wei(100), Wei(500), Wei(0)),  # Edge case: total_assets is 0
            (Wei(1000), Wei(0), Wei(500), Wei(0)),  # Edge case: total_shares is 0
        ],
    )
    def test_to_shares(self, total_assets, total_shares, assets, expected_shares):
        converter = OsTokenConverter(total_assets=total_assets, total_shares=total_shares)
        shares = converter.to_shares(assets)
        assert shares == expected_shares

    @pytest.mark.parametrize(
        'total_assets,total_shares,shares,expected_assets',
        [
            (Wei(1000), Wei(100), Wei(50), Wei(500)),
            (Wei(2000), Wei(200), Wei(100), Wei(1000)),
            (Wei(1000), Wei(0), Wei(50), Wei(0)),  # Edge case: total_shares is 0
            (Wei(0), Wei(100), Wei(50), Wei(0)),  # Edge case: total_assets is 0
        ],
    )
    def test_to_assets(self, total_assets, total_shares, shares, expected_assets):
        converter = OsTokenConverter(total_assets=total_assets, total_shares=total_shares)
        assets = converter.to_assets(shares)
        assert assets == expected_assets
