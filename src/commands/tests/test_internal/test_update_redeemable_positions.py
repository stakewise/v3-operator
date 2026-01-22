import contextlib
from unittest import mock
from unittest.mock import AsyncMock

import pytest
from click.testing import CliRunner
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.commands.internal.update_redeemable_positions import (
    _reduce_boosted_amount,
    calculate_boost_ostoken_shares,
    create_redeemable_positions,
    update_redeemable_positions,
)
from src.config.networks import MAINNET, NETWORKS
from src.config.settings import settings
from src.redeem.os_token_converter import OsTokenConverter
from src.redeem.typings import (
    Allocator,
    LeverageStrategyPosition,
    RedeemablePosition,
    VaultShares,
)


def test_create_redeemable_positions():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()

    # test zero allocators
    result = create_redeemable_positions([], {})
    assert result == []

    # test single vault
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(0),
    }
    result = create_redeemable_positions(allocators, kept_tokens)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150))]

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(100),
    }
    result = create_redeemable_positions(allocators, kept_tokens)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(50))]

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)),
            ],
        ),
        Allocator(
            address=Web3.to_checksum_address(address_2),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(75)),
            ],
        ),
    ]
    kept_tokens = {
        address_1: Wei(0),
        address_2: Wei(75),
    }
    result = create_redeemable_positions(allocators, kept_tokens)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150))]

    # test multiple vaults
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultShares(address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)),
                VaultShares(address=Web3.to_checksum_address(vault_2), minted_shares=Wei(150)),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(0),
    }
    result = create_redeemable_positions(allocators, kept_tokens)
    assert result == [
        RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150)),
        RedeemablePosition(owner=address_1, vault=vault_2, amount=Wei(150)),
    ]


async def test_calculate_boost_ostoken_shares():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    proxy = faker.eth_address()

    os_token_converter = OsTokenConverter(105, 100)

    # empty case
    result = await calculate_boost_ostoken_shares(set(), [], os_token_converter)
    assert result == {}

    # filter by users
    leverage_positions = [
        LeverageStrategyPosition(
            user=address_1,
            vault=vault_1,
            proxy=proxy,
            os_token_shares=Wei(1000),
            exiting_os_token_shares=Wei(500),
            assets=Wei(200),
            exiting_assets=Wei(100),
        ),
        LeverageStrategyPosition(
            user=address_1,
            vault=vault_1,
            proxy=proxy,
            os_token_shares=Wei(1000),
            exiting_os_token_shares=Wei(500),
            assets=Wei(200),
            exiting_assets=Wei(100),
        ),
        LeverageStrategyPosition(
            user=address_2,
            vault=vault_1,
            proxy=proxy,
            os_token_shares=Wei(100),
            exiting_os_token_shares=Wei(0),
            assets=Wei(0),
            exiting_assets=Wei(0),
        ),
        LeverageStrategyPosition(
            user=address_2,
            vault=vault_2,
            proxy=proxy,
            os_token_shares=Wei(3000),
            exiting_os_token_shares=Wei(0),
            assets=Wei(100),
            exiting_assets=Wei(0),
        ),
    ]
    result = await calculate_boost_ostoken_shares(
        {address_1, address_2}, leverage_positions, os_token_converter
    )
    assert result == {address_1: {vault_1: 3570}, address_2: {vault_1: 100, vault_2: 3095}}


def test_reduces_boosted_amount():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    # empty case
    allocators = [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(1000)),
                VaultShares(address=vault_2, minted_shares=Wei(2000)),
            ],
        )
    ]
    boost_ostoken_shares = {}
    result = _reduce_boosted_amount(allocators, boost_ostoken_shares)
    assert result == [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(1000)),
                VaultShares(address=vault_2, minted_shares=Wei(2000)),
            ],
        )
    ]
    # basic reduction
    allocators = [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(500)),
            ],
        ),
        Allocator(
            address=address_2,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(1000)),
                VaultShares(address=vault_2, minted_shares=Wei(2000)),
            ],
        ),
    ]
    boost_ostoken_shares = {
        address_1: {
            vault_1: Wei(300),
        },
        address_2: {
            vault_1: Wei(500),
            vault_2: Wei(1500),
        },
    }
    result = _reduce_boosted_amount(allocators, boost_ostoken_shares)
    assert result == [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(200)),
            ],
        ),
        Allocator(
            address=address_2,
            vault_shares=[
                VaultShares(address=vault_1, minted_shares=Wei(500)),
                VaultShares(address=vault_2, minted_shares=Wei(500)),
            ],
        ),
    ]


@pytest.mark.usefixtures('_init_config')
class TestUpdateRedeemablePositions:
    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_update_redeemable_positions(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        address_1 = faker.eth_address()
        address_2 = faker.eth_address()
        vault_1 = faker.eth_address()
        vault_2 = faker.eth_address()
        # mocked data
        allocators = [
            {
                'vault': {
                    'id': vault_1.lower(),
                },
                'id': address_1.lower(),
                'address': address_1,
                'mintedOsTokenShares': 1,
            }
        ]
        leverage_positions = [
            {
                'user': address_1,
                'vault': {
                    'id': vault_1.lower(),
                },
                'proxy': faker.eth_address(),
                'osTokenShares': '1000',
                'exitingOsTokenShares': '500',
                'assets': '200',
                'exitingAssets': '100',
            },
            {
                'user': address_2,
                'vault': {
                    'id': vault_2.lower(),
                },
                'proxy': faker.eth_address(),
                'osTokenShares': '3000',
                'exitingOsTokenShares': '0',
                'assets': '100',
                'exitingAssets': '0',
            },
        ]
        os_token_holders = [
            {
                'id': address_1.lower(),
                'balance': '1000',
            },
            {
                'id': address_2.lower(),
                'balance': '5000',
            },
        ]
        mock_protocol_data = [
            {
                'id': 'stakewise',
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': '0x1234567890abcdef1234567890abcdef12345678',
                                    'chain': 'eth',
                                    'amount': '57',
                                }
                            ]
                        }
                    }
                ],
            },
            {
                'id': 'other',
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': settings.network_config.OS_TOKEN_CONTRACT_ADDRESS,
                                    'chain': 'eth',
                                    'amount': '555',
                                }
                            ]
                        }
                    }
                ],
            },
        ]
        os_token_converter = OsTokenConverter(105, 100)
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--arbitrum-endpoint',
            execution_endpoints,
            '--verbose',
        ]
        with (
            patch_ipfs_upload(),
            patch_latest_block(11),
            patch_get_erc_balance(11),
            patch_os_token_redeemer_contract_nonce(6),
            patch_os_token_arbitrum_contract_address(),
            mock.patch(
                'src.redeem.graph.graph_client.fetch_pages',
                side_effect=[allocators, leverage_positions, os_token_holders],
            ),
            mock.patch(
                'src.commands.internal.update_redeemable_positions.create_os_token_converter',
                return_value=os_token_converter,
            ),
            mock.patch(
                'src.redeem.api_client.APIClient._fetch_json', return_value=mock_protocol_data
            ),
        ):
            result = runner.invoke(update_redeemable_positions, args)
            assert result.exit_code == 0
            assert '' == result.output.strip()


@contextlib.contextmanager
def patch_ipfs_upload():
    with mock.patch(
        'src.commands.internal.update_redeemable_positions.build_ipfs_upload_clients',
        new=AsyncMock(),
    ) as ipfs_mock:
        ipfs_mock.upload_json = 'bafk...'
        yield


@contextlib.contextmanager
def patch_latest_block(block_number):
    with mock.patch(
        'src.commands.internal.update_redeemable_positions.execution_client', new=AsyncMock()
    ) as execution_client_mock:
        execution_client_mock.eth.get_block_number.return_value = block_number
        yield


@contextlib.contextmanager
def patch_get_erc_balance(balance):
    with mock.patch(
        'src.commands.internal.update_redeemable_positions.Erc20Contract.get_balance',
        return_value=balance,
    ):
        yield


@contextlib.contextmanager
def patch_os_token_arbitrum_contract_address():
    with mock.patch.object(
        settings.network_config,
        'OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS',
        NETWORKS[MAINNET].OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS,
    ):
        yield


@contextlib.contextmanager
def patch_os_token_redeemer_contract_nonce(nonce):
    with mock.patch(
        'src.commands.internal.update_redeemable_positions.os_token_redeemer_contract.nonce',
        return_value=nonce,
    ):
        yield
