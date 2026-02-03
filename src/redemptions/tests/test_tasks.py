import itertools
import random
from contextlib import contextmanager
from decimal import Decimal
from unittest import mock

import pytest
from eth_typing import HexStr
from sw_utils.tests import faker
from web3 import Web3

from src.redemptions.os_token_converter import os_token_vault_controller_contract
from src.common.tests.utils import parse_wei
from src.redemptions.tasks import (
    aggregate_redemption_assets_by_vaults,
    batch_size,
    ipfs_fetch_client,
    os_token_redeemer_contract,
)
from src.redemptions.tests.factories import create_redeemable_positions
from src.redemptions.typings import RedeemablePositions


class TestAggregateRedemptionAssetsByVaults:
    async def test_redeemable_positions_empty(self):
        redeemable_positions = RedeemablePositions(merkle_root=HexStr('0x'), ipfs_hash='')
        total_redemption_assets = Web3.to_wei(100, 'ether')

        with self.patch(redeemable_positions=redeemable_positions):
            redemption_assets_by_vaults = await aggregate_redemption_assets_by_vaults(
                total_redemption_assets
            )
            assert redemption_assets_by_vaults == {}

    @pytest.mark.parametrize(
        'total_redemption_assets, leaf_shares, processed_shares, expected_redeemed_assets',
        [
            # Case 1. Total redemption shares exceeds total leaf shares
            parse_wei(['100 ether', '10 ether', '0 ether', '11 ether']),
            parse_wei(['100 ether', '10 ether', '2 ether', '8.8 ether']),
            parse_wei(['100 ether', '10 ether', '10 ether', '0 ether']),
            parse_wei(['100 ether', '10 ether', '11 ether', '0 ether']),
            #
            # Case 2. Total redemption shares is less than total leaf shares
            parse_wei(['1.1 ether', '10 ether', '0 ether', '1.1 ether']),
        ],
    )
    async def test_redeemable_positions_1_vault(
        self, total_redemption_assets, leaf_shares, processed_shares, expected_redeemed_assets
    ):
        """
        The case of single vault.
        """
        vault_1 = faker.eth_address()
        redeemable_positions_ipfs_data = [
            {
                'owner': faker.eth_address(),
                'vault': vault_1,
                'amount': leaf_shares,
            }
        ]
        processed_shares_batch = [processed_shares]

        with self.patch(
            redeemable_positions_ipfs_data=redeemable_positions_ipfs_data,
            processed_shares_batch=processed_shares_batch,
        ):
            redemption_assets_by_vaults = await aggregate_redemption_assets_by_vaults(
                total_redemption_assets
            )
            assert len(redemption_assets_by_vaults) <= 1  # length can be 0 if no assets to redeem
            assert redemption_assets_by_vaults[vault_1] == expected_redeemed_assets

    @pytest.mark.parametrize(
        'total_redemption_assets, leaf_shares, processed_shares, expected_redeemed_assets',
        [
            # Case 1. Total redemption shares exceeds total leaf shares
            parse_wei(
                [
                    '100 ether',
                    {'vault_1': '10 ether', 'vault_2': '20 ether'},  # leaf shares
                    {'vault_1': '0 ether', 'vault_2': '0 ether'},  # processed shares
                    {'vault_1': '11 ether', 'vault_2': '22 ether'},  # expected redeemed assets
                ]
            ),
            #
            # Case 2. Total redemption shares is greater than vault 1 leaf shares
            # but less than total leaf shares
            parse_wei(
                [
                    '15 ether',
                    {'vault_1': '10 ether', 'vault_2': '20 ether'},  # leaf shares
                    {'vault_1': '0 ether', 'vault_2': '0 ether'},  # processed shares
                    {'vault_1': '11 ether', 'vault_2': '4 ether'},  # expected redeemed assets
                ]
            ),
            # Case 3. Total redemption shares is less than vault 1 leaf shares
            parse_wei(
                [
                    '5 ether',
                    {'vault_1': '10 ether', 'vault_2': '20 ether'},  # leaf shares
                    {'vault_1': '0 ether', 'vault_2': '0 ether'},  # processed shares
                    {'vault_1': '5 ether', 'vault_2': '0 ether'},  # expected redeemed assets
                ]
            ),
        ],
    )
    async def test_redeemable_positions_2_vaults(
        self, total_redemption_assets, leaf_shares, processed_shares, expected_redeemed_assets
    ):
        """
        The case of two vaults.
        """
        vault_1 = faker.eth_address()
        vault_2 = faker.eth_address()
        redeemable_positions_ipfs_data = [
            {
                'owner': faker.eth_address(),
                'vault': vault_1,
                'amount': leaf_shares['vault_1'],
            },
            {
                'owner': faker.eth_address(),
                'vault': vault_2,
                'amount': leaf_shares['vault_2'],
            },
        ]
        processed_shares_batch = [processed_shares['vault_1'], processed_shares['vault_2']]

        with self.patch(
            redeemable_positions_ipfs_data=redeemable_positions_ipfs_data,
            processed_shares_batch=processed_shares_batch,
        ):
            redemption_assets_by_vaults = await aggregate_redemption_assets_by_vaults(
                total_redemption_assets
            )
            # length can be less than 2 if no assets to redeem
            assert len(redemption_assets_by_vaults) <= 2
            # allow 1 wei difference due to rounding
            assert (
                abs(redemption_assets_by_vaults[vault_1] - expected_redeemed_assets['vault_1']) <= 1
            )
            assert (
                abs(redemption_assets_by_vaults[vault_2] - expected_redeemed_assets['vault_2']) <= 1
            )

    async def test_2_vaults_many_users(self):
        """
        The case of two vaults with many users.
        Check aggregation by vault and batching.
        """
        vault_1 = faker.eth_address()
        vault_2 = faker.eth_address()
        redeemable_positions_ipfs_data = []
        processed_shares = []
        redemption_shares_vault_1 = 0
        redemption_shares_vault_2 = 0

        redemption_users_count_per_vault = int(1.5 * batch_size)
        processed_shares_max_index = 2 * batch_size

        # Create 50 users per vault
        for index in range(50):
            leaf_shares_1 = Web3.to_wei(random.randint(1, 5), 'ether')
            redeemable_positions_ipfs_data.append(
                {
                    'owner': faker.eth_address(),
                    'vault': vault_1,
                    'amount': leaf_shares_1,
                }
            )
            if index < redemption_users_count_per_vault:
                redemption_shares_vault_1 += Web3.to_wei(1, 'ether')

            if index < processed_shares_max_index:
                processed_shares.append(leaf_shares_1 - Web3.to_wei(1, 'ether'))

            leaf_shares_2 = Web3.to_wei(random.randint(1, 5), 'ether')
            redeemable_positions_ipfs_data.append(
                {
                    'owner': faker.eth_address(),
                    'vault': vault_2,
                    'amount': leaf_shares_2,
                }
            )

            if index < redemption_users_count_per_vault:
                redemption_shares_vault_2 += Web3.to_wei('0.5', 'ether')

            if index < processed_shares_max_index:
                processed_shares.append(leaf_shares_2 - Web3.to_wei('0.5', 'ether'))

        total_redemption_shares = redemption_shares_vault_1 + redemption_shares_vault_2
        total_redemption_assets = total_redemption_shares * Decimal('1.1')

        processed_shares_batches = list(itertools.batched(processed_shares, batch_size))

        with self.patch(
            redeemable_positions_ipfs_data=redeemable_positions_ipfs_data,
            processed_shares_batches=processed_shares_batches,
        ):
            redemption_assets_by_vaults = await aggregate_redemption_assets_by_vaults(
                total_redemption_assets
            )
            assert len(redemption_assets_by_vaults) == 2
            assert redemption_assets_by_vaults[vault_1] == redemption_shares_vault_1 * Decimal(
                '1.1'
            )
            assert redemption_assets_by_vaults[vault_2] == redemption_shares_vault_2 * Decimal(
                '1.1'
            )

    @contextmanager
    def patch(
        self,
        os_token_assets_to_shares_ratio: Decimal = Decimal('1.1'),
        redeemable_positions: RedeemablePositions | None = None,
        redeemable_positions_ipfs_data: list[dict] | None = None,
        processed_shares_batch: list[int] | None = None,
        processed_shares_batches: list[list[int]] | None = None,
    ):
        if redeemable_positions is None:
            redeemable_positions = create_redeemable_positions()

        total_assets = Web3.to_wei(100 * os_token_assets_to_shares_ratio, 'ether')
        total_shares = Web3.to_wei(100, 'ether')

        redeemable_positions_ipfs_data = redeemable_positions_ipfs_data or []

        if processed_shares_batch is None:
            processed_shares_batch = [0] * len(redeemable_positions_ipfs_data)

        if processed_shares_batches is None:
            processed_shares_batches = [processed_shares_batch]

        with mock.patch.object(
            os_token_redeemer_contract, 'redeemable_positions', return_value=redeemable_positions
        ), mock.patch.object(
            os_token_redeemer_contract, 'nonce', return_value=0
        ), mock.patch.object(
            os_token_vault_controller_contract, 'total_assets', return_value=total_assets
        ), mock.patch.object(
            os_token_vault_controller_contract, 'total_shares', return_value=total_shares
        ), mock.patch.object(
            ipfs_fetch_client, 'fetch_json', return_value=redeemable_positions_ipfs_data
        ), mock.patch(
            'src.redemptions.tasks.get_processed_shares_batch', side_effect=processed_shares_batches
        ):
            yield

    def get_processed_shares_batch(self, redeemable_positions_batch, nonce) -> list[int]:
        """A placeholder for the patched method."""
        return [0] * len(redeemable_positions_batch)
