import random
from unittest.mock import patch

import pytest
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.redemptions.graph import graph_get_allocators
from src.redemptions.typings import Allocator, VaultOsTokenPosition


@pytest.mark.usefixtures('fake_settings')
async def test_graph_get_allocators():
    address_1 = faker.eth_address().lower()
    address_2 = faker.eth_address().lower()
    vault_1 = faker.eth_address().lower()
    vault_2 = faker.eth_address().lower()

    with patch('src.redemptions.graph.graph_client.fetch_pages', return_value=[]):
        result = await graph_get_allocators(random.randint(1, 1000000))
    assert result == []

    mock_response = [
        {
            'address': address_1,
            'vault': {'id': vault_1, 'osTokenConfig': {'id': '2'}},
            'mintedOsTokenShares': '0',
            'ltv': '0',
        },
        {
            'address': address_2,
            'vault': {'id': vault_2, 'osTokenConfig': {'id': '2'}},
            'mintedOsTokenShares': '1000',
            'ltv': '0.7',
        },
    ]
    with patch('src.redemptions.graph.graph_client.fetch_pages', return_value=mock_response):
        result = await graph_get_allocators(random.randint(1, 1000000))
    assert result == [
        Allocator(
            address=Web3.to_checksum_address(address_2),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(1000), ltv=0.7
                )
            ],
        )
    ]

    mock_response = [
        {
            'address': address_1,
            'vault': {'id': vault_1, 'osTokenConfig': {'id': '2'}},
            'mintedOsTokenShares': '150',
            'ltv': '0.5',
        },
        {
            'address': address_1,
            'vault': {'id': vault_2, 'osTokenConfig': {'id': '2'}},
            'mintedOsTokenShares': '1000',
            'ltv': '0.7',
        },
    ]
    with patch('src.redemptions.graph.graph_client.fetch_pages', return_value=mock_response):
        result = await graph_get_allocators(random.randint(1, 1000000))
    assert result == [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150), ltv=0.5
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(1000), ltv=0.7
                ),
            ],
        )
    ]


@pytest.mark.usefixtures('fake_settings')
async def test_graph_get_allocators_filters_legacy_vaults():
    """Allocator entries whose vault has osTokenConfig.id == '1' must be skipped."""
    address_1 = faker.eth_address().lower()
    address_2 = faker.eth_address().lower()
    legacy_vault = faker.eth_address().lower()
    vault = faker.eth_address().lower()

    mock_response = [
        {
            'address': address_1,
            'vault': {'id': legacy_vault, 'osTokenConfig': {'id': '1'}},
            'mintedOsTokenShares': '500',
            'ltv': '0.6',
        },
        {
            'address': address_2,
            'vault': {'id': vault, 'osTokenConfig': {'id': '2'}},
            'mintedOsTokenShares': '1000',
            'ltv': '0.7',
        },
    ]
    with patch('src.redemptions.graph.graph_client.fetch_pages', return_value=mock_response):
        result = await graph_get_allocators(random.randint(1, 1000000))
    assert result == [
        Allocator(
            address=Web3.to_checksum_address(address_2),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault), minted_shares=Wei(1000), ltv=0.7
                )
            ],
        )
    ]

    # All entries belong to legacy vaults -> empty result.
    mock_response = [
        {
            'address': address_1,
            'vault': {'id': legacy_vault, 'osTokenConfig': {'id': '1'}},
            'mintedOsTokenShares': '500',
            'ltv': '0.6',
        },
    ]
    with patch('src.redemptions.graph.graph_client.fetch_pages', return_value=mock_response):
        result = await graph_get_allocators(random.randint(1, 1000000))
    assert result == []
