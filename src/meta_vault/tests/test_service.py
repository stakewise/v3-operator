from collections import defaultdict
from unittest.mock import AsyncMock, patch

import pytest
from sw_utils.tests import faker

from src.common.contracts import MetaVaultContract
from src.meta_vault.service import distribute_meta_vault_redemption_assets
from src.meta_vault.typings import SubVaultRedemption


@pytest.fixture
def vaults():
    return {
        'vault1': faker.eth_address(),
        'vault2': faker.eth_address(),
        'meta_vault': faker.eth_address(),
        'nested_meta_vault': faker.eth_address(),
        'sub_vault1': faker.eth_address(),
        'sub_vault2': faker.eth_address(),
    }


class TestDistributeMetaVaultRedemptionAssets:
    async def test_distribute_no_meta_vaults(self, vaults):
        assets = defaultdict(
            int,
            {
                vaults['vault1']: 100,
                vaults['vault2']: 200,
            },
        )

        with patch('src.meta_vault.service.is_meta_vault', new=AsyncMock(return_value=False)):
            result = await distribute_meta_vault_redemption_assets(assets)
            assert dict(result) == {
                vaults['vault1']: 100,
                vaults['vault2']: 200,
            }

    async def test_distribute_single_meta_vault(self, vaults):
        assets = defaultdict(
            int,
            {
                vaults['meta_vault']: 300,
                vaults['vault1']: 100,
            },
        )

        def is_meta_vault_side_effect(addr):
            return addr == vaults['meta_vault']

        sub_vault_redemptions = [
            SubVaultRedemption(vault=vaults['sub_vault1'], assets=120),
            SubVaultRedemption(vault=vaults['sub_vault2'], assets=180),
        ]

        with patch(
            'src.meta_vault.service.is_meta_vault',
            new=AsyncMock(side_effect=is_meta_vault_side_effect),
        ), patch.object(
            MetaVaultContract,
            'calculate_sub_vaults_redemptions',
            return_value=sub_vault_redemptions,
        ):
            result = await distribute_meta_vault_redemption_assets(assets)
            assert dict(result) == {
                vaults['vault1']: 100,
                vaults['sub_vault1']: 120,
                vaults['sub_vault2']: 180,
            }

    async def test_distribute_nested_meta_vaults(self, vaults):
        assets = defaultdict(
            int,
            {
                vaults['meta_vault']: 500,
            },
        )

        def is_meta_vault_side_effect(addr):
            return addr in {vaults['meta_vault'], vaults['nested_meta_vault']}

        # meta_vault splits to nested_meta_vault and vault2
        meta_vault_redemptions = [
            SubVaultRedemption(vault=vaults['nested_meta_vault'], assets=300),
            SubVaultRedemption(vault=vaults['vault2'], assets=200),
        ]
        # nested_meta_vault splits to sub_vault1 and sub_vault2
        nested_meta_vault_redemptions = [
            SubVaultRedemption(vault=vaults['sub_vault1'], assets=100),
            SubVaultRedemption(vault=vaults['sub_vault2'], assets=200),
        ]

        async def calculate_sub_vaults_redemptions_side_effect(self, assets, block_number=None):
            if self.address == vaults['meta_vault']:
                return meta_vault_redemptions
            elif self.address == vaults['nested_meta_vault']:
                return nested_meta_vault_redemptions
            else:
                return defaultdict(int)

        with patch(
            'src.meta_vault.service.is_meta_vault',
            new=AsyncMock(side_effect=is_meta_vault_side_effect),
        ), patch.object(
            MetaVaultContract,
            'calculate_sub_vaults_redemptions',
            new=calculate_sub_vaults_redemptions_side_effect,
        ):
            result = await distribute_meta_vault_redemption_assets(assets)
            assert dict(result) == {
                vaults['vault2']: 200,
                vaults['sub_vault1']: 100,
                vaults['sub_vault2']: 200,
            }

    async def test_distribute_mixed_meta_and_non_meta(self, vaults):
        assets = defaultdict(
            int,
            {
                vaults['vault1']: 50,
                vaults['meta_vault']: 150,
                vaults['vault2']: 75,
            },
        )

        def is_meta_vault_side_effect(addr):
            return addr == vaults['meta_vault']

        sub_vault_redemptions = [
            SubVaultRedemption(vault=vaults['sub_vault1'], assets=60),
            SubVaultRedemption(vault=vaults['sub_vault2'], assets=90),
        ]

        with patch(
            'src.meta_vault.service.is_meta_vault',
            new=AsyncMock(side_effect=is_meta_vault_side_effect),
        ), patch.object(
            MetaVaultContract,
            'calculate_sub_vaults_redemptions',
            return_value=sub_vault_redemptions,
        ):
            result = await distribute_meta_vault_redemption_assets(assets)
            assert dict(result) == {
                vaults['vault1']: 50,
                vaults['vault2']: 75,
                vaults['sub_vault1']: 60,
                vaults['sub_vault2']: 90,
            }
