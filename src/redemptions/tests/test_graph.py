from unittest.mock import patch

import pytest
from eth_typing import BlockNumber
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.redemptions.graph import graph_get_allocators_from_vaults
from src.redemptions.typings import Allocator, VaultOsTokenPosition


@pytest.mark.usefixtures('fake_settings')
async def test_graph_get_allocators_from_vaults():
    address_1 = faker.eth_address().lower()
    address_2 = faker.eth_address().lower()
    vault_1 = Web3.to_checksum_address(faker.eth_address())
    vault_2 = Web3.to_checksum_address(faker.eth_address())

    vault_1_response = [
        {'address': address_1, 'mintedOsTokenShares': '150', 'ltv': '0.5'},
        {'address': address_2, 'mintedOsTokenShares': '1000', 'ltv': '0.7'},
    ]
    vault_2_response = [
        {'address': address_1, 'mintedOsTokenShares': '2000', 'ltv': '0.8'},
    ]

    with patch(
        'src.redemptions.graph.graph_client.fetch_pages',
        side_effect=[vault_1_response, vault_2_response],
    ):
        result = await graph_get_allocators_from_vaults([vault_1, vault_2], BlockNumber(123))

    by_address = {a.address: a for a in result}
    assert by_address[Web3.to_checksum_address(address_1)] == Allocator(
        address=Web3.to_checksum_address(address_1),
        vault_os_token_positions=[
            VaultOsTokenPosition(address=vault_1, minted_shares=Wei(150), ltv=0.5),
            VaultOsTokenPosition(address=vault_2, minted_shares=Wei(2000), ltv=0.8),
        ],
    )
    assert by_address[Web3.to_checksum_address(address_2)] == Allocator(
        address=Web3.to_checksum_address(address_2),
        vault_os_token_positions=[
            VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000), ltv=0.7),
        ],
    )
