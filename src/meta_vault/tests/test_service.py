from collections import defaultdict
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from eth_typing import BlockNumber, ChecksumAddress
from sw_utils.tests import faker
from web3.types import Wei

from src.meta_vault.contracts import MetaVaultContract, SubVaultsRegistryContract
from src.meta_vault.service import distribute_meta_vault_redemption_assets
from src.meta_vault.typings import SubVaultRedemption


@pytest.fixture
def vaults() -> dict[str, ChecksumAddress]:
    return {
        'vault1': faker.eth_address(),
        'vault2': faker.eth_address(),
        'meta_vault': faker.eth_address(),
        'nested_meta_vault': faker.eth_address(),
        'sub_vault1': faker.eth_address(),
        'sub_vault2': faker.eth_address(),
    }


class TestDistributeMetaVaultRedemptionAssets:
    async def test_distribute_no_meta_vaults(self, vaults: dict[str, ChecksumAddress]) -> None:
        assets = defaultdict(
            lambda: Wei(0),
            {
                vaults['vault1']: Wei(100),
                vaults['vault2']: Wei(200),
            },
        )

        with patch('src.meta_vault.service.is_meta_vault', new=AsyncMock(return_value=False)):
            result = await distribute_meta_vault_redemption_assets(assets)
            assert dict(result) == {
                vaults['vault1']: Wei(100),
                vaults['vault2']: Wei(200),
            }

    async def test_distribute_single_meta_vault(self, vaults: dict[str, ChecksumAddress]) -> None:
        assets = defaultdict(
            lambda: Wei(0),
            {
                vaults['meta_vault']: Wei(300),
                vaults['vault1']: Wei(100),
            },
        )

        def is_meta_vault_side_effect(addr: ChecksumAddress) -> bool:
            return addr == vaults['meta_vault']

        sub_vault_redemptions = [
            SubVaultRedemption(vault=vaults['sub_vault1'], assets=Wei(120)),
            SubVaultRedemption(vault=vaults['sub_vault2'], assets=Wei(180)),
        ]

        with (
            patch(
                'src.meta_vault.service.is_meta_vault',
                new=AsyncMock(side_effect=is_meta_vault_side_effect),
            ),
            patch.object(
                MetaVaultContract,
                'sub_vaults_registry',
                return_value=faker.eth_address(),
            ),
            patch.object(
                SubVaultsRegistryContract,
                'calculate_sub_vaults_redemptions',
                return_value=sub_vault_redemptions,
            ),
        ):
            result = await distribute_meta_vault_redemption_assets(assets)
            assert dict(result) == {
                vaults['vault1']: Wei(100),
                vaults['meta_vault']: Wei(300),
                vaults['sub_vault1']: Wei(120),
                vaults['sub_vault2']: Wei(180),
            }

    async def test_distribute_nested_meta_vaults(self, vaults: dict[str, ChecksumAddress]) -> None:
        assets = defaultdict(
            lambda: Wei(0),
            {
                vaults['meta_vault']: Wei(500),
            },
        )

        def is_meta_vault_side_effect(addr: ChecksumAddress) -> bool:
            return addr in {vaults['meta_vault'], vaults['nested_meta_vault']}

        # meta_vault splits to nested_meta_vault and vault2
        meta_vault_redemptions = [
            SubVaultRedemption(vault=vaults['nested_meta_vault'], assets=Wei(300)),
            SubVaultRedemption(vault=vaults['vault2'], assets=Wei(200)),
        ]
        # nested_meta_vault splits to sub_vault1 and sub_vault2
        nested_meta_vault_redemptions = [
            SubVaultRedemption(vault=vaults['sub_vault1'], assets=Wei(100)),
            SubVaultRedemption(vault=vaults['sub_vault2'], assets=Wei(200)),
        ]

        async def calculate_sub_vaults_redemptions_side_effect(
            self: Any, assets: Wei, block_number: BlockNumber | None = None
        ) -> list[SubVaultRedemption]:
            if self.address == vaults['meta_vault']:
                return meta_vault_redemptions
            elif self.address == vaults['nested_meta_vault']:
                return nested_meta_vault_redemptions
            else:
                return []

        async def sub_vaults_registry_side_effect(self: Any) -> ChecksumAddress:
            return self.address

        with (
            patch(
                'src.meta_vault.service.is_meta_vault',
                new=AsyncMock(side_effect=is_meta_vault_side_effect),
            ),
            patch.object(
                MetaVaultContract,
                'sub_vaults_registry',
                new=sub_vaults_registry_side_effect,
            ),
            patch.object(
                SubVaultsRegistryContract,
                'calculate_sub_vaults_redemptions',
                new=calculate_sub_vaults_redemptions_side_effect,
            ),
        ):
            result = await distribute_meta_vault_redemption_assets(assets)
            assert dict(result) == {
                vaults['meta_vault']: Wei(500),
                vaults['nested_meta_vault']: Wei(300),
                vaults['vault2']: Wei(200),
                vaults['sub_vault1']: Wei(100),
                vaults['sub_vault2']: Wei(200),
            }

    async def test_distribute_mixed_meta_and_non_meta(
        self, vaults: dict[str, ChecksumAddress]
    ) -> None:
        assets = defaultdict(
            lambda: Wei(0),
            {
                vaults['vault1']: Wei(50),
                vaults['meta_vault']: Wei(150),
                vaults['vault2']: Wei(75),
            },
        )

        def is_meta_vault_side_effect(addr: ChecksumAddress) -> bool:
            return addr == vaults['meta_vault']

        sub_vault_redemptions = [
            SubVaultRedemption(vault=vaults['sub_vault1'], assets=Wei(60)),
            SubVaultRedemption(vault=vaults['sub_vault2'], assets=Wei(90)),
        ]

        with (
            patch(
                'src.meta_vault.service.is_meta_vault',
                new=AsyncMock(side_effect=is_meta_vault_side_effect),
            ),
            patch.object(
                MetaVaultContract,
                'sub_vaults_registry',
                return_value=faker.eth_address(),
            ),
            patch.object(
                SubVaultsRegistryContract,
                'calculate_sub_vaults_redemptions',
                return_value=sub_vault_redemptions,
            ),
        ):
            result = await distribute_meta_vault_redemption_assets(assets)
            assert dict(result) == {
                vaults['vault1']: Wei(50),
                vaults['meta_vault']: Wei(150),
                vaults['vault2']: Wei(75),
                vaults['sub_vault1']: Wei(60),
                vaults['sub_vault2']: Wei(90),
            }
