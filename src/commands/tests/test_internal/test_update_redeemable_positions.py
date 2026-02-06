import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from sw_utils.tests import faker
from web3 import Web3
from web3.types import ChecksumAddress, Wei

from src.commands.internal.update_redeemable_positions import (
    _reduce_boosted_amount,
    calculate_boost_ostoken_shares,
    create_redeemable_positions,
    update_redeemable_positions,
)
from src.config.networks import MAINNET, NETWORKS
from src.config.settings import settings
from src.redemptions.os_token_converter import OsTokenConverter
from src.redemptions.typings import (
    Allocator,
    LeverageStrategyPosition,
    RedeemablePosition,
    VaultOsTokenPosition,
)

os_token_contract_address = NETWORKS[MAINNET].OS_TOKEN_CONTRACT_ADDRESS


def test_create_redeemable_positions_zero_allocators():
    result = create_redeemable_positions([], {}, 0)
    assert result == []


def test_create_redeemable_positions_single_vault():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)
                ),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(0),
    }
    result = create_redeemable_positions(allocators, kept_tokens, 0)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150))]


def test_create_redeemable_positions_kept_tokens():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)
                ),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(100),
    }
    result = create_redeemable_positions(allocators, kept_tokens, 0)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(50))]


def test_create_redeemable_positions_multiple_allocators():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)
                ),
            ],
        ),
        Allocator(
            address=Web3.to_checksum_address(address_2),
            vault_shares=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(75)
                ),
            ],
        ),
    ]
    kept_tokens = {
        address_1: Wei(0),
        address_2: Wei(75),
    }
    result = create_redeemable_positions(allocators, kept_tokens, 0)
    assert result == [RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150))]


def test_create_redeemable_positions_multiple_vaults_1():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150)
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(150)
                ),
            ],
        )
    ]
    result = create_redeemable_positions(allocators, {}, 0)
    assert result == [
        RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(150)),
        RedeemablePosition(owner=address_1, vault=vault_2, amount=Wei(150)),
    ]


def test_create_redeemable_positions_multiple_vaults_2():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(333)
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(666)
                ),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(100),
    }
    result = create_redeemable_positions(allocators, kept_tokens, 0)
    assert result == [
        RedeemablePosition(owner=address_1, vault=vault_2, amount=Wei(600)),
        RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(299)),
    ]


def test_create_redeemable_positions_multiple_vaults_3():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(333)
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(666)
                ),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(100),
    }
    result = create_redeemable_positions(allocators, kept_tokens, 0)
    assert result == [
        RedeemablePosition(owner=address_1, vault=vault_2, amount=Wei(600)),
        RedeemablePosition(owner=address_1, vault=vault_1, amount=Wei(299)),
    ]


def test_create_redeemable_positions_min_minted_shares():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_shares=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(333)
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(666)
                ),
            ],
        )
    ]
    kept_tokens = {
        address_1: Wei(100),
    }
    result = create_redeemable_positions(allocators, kept_tokens, 300)
    assert result == [
        RedeemablePosition(owner=address_1, vault=vault_2, amount=Wei(600)),
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
    assert result == {
        (address_1, vault_1): 3570,
        (address_2, vault_1): 100,
        (address_2, vault_2): 3095,
    }


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
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000)),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(2000)),
            ],
        )
    ]
    boost_ostoken_shares = {}
    result = _reduce_boosted_amount(allocators, boost_ostoken_shares)
    assert result == [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000)),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(2000)),
            ],
        )
    ]
    # basic reduction
    allocators = [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(500)),
            ],
        ),
        Allocator(
            address=address_2,
            vault_shares=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000)),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(2000)),
            ],
        ),
    ]
    boost_ostoken_shares = {
        (address_1, vault_1): Wei(300),
        (address_2, vault_1): Wei(500),
        (address_2, vault_2): Wei(1500),
    }

    result = _reduce_boosted_amount(allocators, boost_ostoken_shares)
    assert result == [
        Allocator(
            address=address_1,
            vault_shares=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(200)),
            ],
        ),
        Allocator(
            address=address_2,
            vault_shares=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(500)),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(500)),
            ],
        ),
    ]


@pytest.mark.usefixtures('_init_config')
class TestUpdateRedeemablePositions:
    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_basic_call(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        # hardcoded to check merkle root
        address_1 = '0x2242b8ab71521f6abEE4B4D83195E70AcB08727a'
        address_2 = '0x24c8DBBC3d1C35C4159787b1f7a62bea1A814242'
        vault_1 = '0xEd735de172272C03CA6F60c1d90D83D9CFB46D22'
        vault_2 = '0xe8Ea1025b49D2B51C536cFBc0833F021ba4c6903'
        allocators = [
            {
                'vault': {
                    'id': vault_1.lower(),
                },
                'id': address_1.lower(),
                'address': address_1,
                'mintedOsTokenShares': Web3.to_wei(10, 'ether'),
            },
            {
                'vault': {
                    'id': vault_2.lower(),
                },
                'id': address_2.lower(),
                'address': address_2,
                'mintedOsTokenShares': Web3.to_wei(12, 'ether'),
            },
        ]
        leverage_positions = [
            {
                'user': address_1,
                'vault': {
                    'id': vault_1.lower(),
                },
                'proxy': faker.eth_address(),
                'osTokenShares': Web3.to_wei(1, 'ether'),
                'exitingOsTokenShares': Web3.to_wei(0.1, 'ether'),
                'assets': Web3.to_wei(0.1, 'ether'),
                'exitingAssets': Web3.to_wei(0.05, 'ether'),
            },
        ]
        os_token_holders = [
            {
                'id': address_1.lower(),
                'balance': Web3.to_wei(3, 'ether'),
            },
            {
                'id': address_2.lower(),
                'balance': Web3.to_wei(12, 'ether'),
            },
        ]
        mock_protocol_data = [
            {
                'id': 'stakewise',
                'chain': 'eth',
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': '0x1234567890abcdef1234567890abcdef12345678',
                                    'chain': 'eth',
                                    'amount': '0.5',
                                }
                            ]
                        }
                    }
                ],
            },
            {
                'id': 'aave3',
                'chain': 'eth',
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': os_token_contract_address,
                                    'chain': 'eth',
                                    'amount': '2',
                                }
                            ]
                        }
                    }
                ],
            },
            {
                'id': 'balancer',
                'chain': 'eth',
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': os_token_contract_address,
                                    'chain': 'eth',
                                    'amount': '0.2',
                                }
                            ]
                        }
                    }
                ],
            },
        ]
        os_token_converter = OsTokenConverter(110, 100)
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
            patch_latest_block(11),
            patch_get_erc_balance(Web3.to_wei(1, 'ether')),
            patch_os_token_redeemer_contract_nonce(6),
            patch_os_token_arbitrum_contract_address(),
            patch_os_token_contract_address(os_token_contract_address),
            patch_os_token_converter(os_token_converter),
            patch_api_client(mock_protocol_data),
            patch(
                'src.redemptions.graph.graph_client.fetch_pages',
                side_effect=[allocators, leverage_positions, os_token_holders],
            ),
            patch_ipfs_client() as mock_upload_json,
        ):
            result = runner.invoke(update_redeemable_positions, args, input='\n')
            assert result.exit_code == 0
            mock_upload_json.assert_called_once_with(
                [{'owner': address_1, 'vault': vault_1, 'amount': '2563636363636363637'}]
            )
            assert (
                '0x9bb2ee30813b89e23e6bbfa1b78706c008f71489750571c81d3b33289647bec1'
                in result.output.strip()
            )

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_full_position(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        # hardcoded to check merkle root
        address_1 = '0x2242b8ab71521f6abEE4B4D83195E70AcB08727a'
        vault_1 = '0xEd735de172272C03CA6F60c1d90D83D9CFB46D22'
        allocators = [
            {
                'vault': {
                    'id': vault_1.lower(),
                },
                'id': address_1.lower(),
                'address': address_1,
                'mintedOsTokenShares': Web3.to_wei(10, 'ether'),
            },
        ]
        leverage_positions = []
        os_token_holders = []
        mock_protocol_data = []
        os_token_converter = OsTokenConverter(110, 100)
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
            patch_latest_block(11),
            patch_get_erc_balance(Web3.to_wei(0, 'ether')),
            patch_os_token_redeemer_contract_nonce(6),
            patch_os_token_arbitrum_contract_address(),
            patch_os_token_contract_address(os_token_contract_address),
            patch_os_token_converter(os_token_converter),
            patch_api_client(mock_protocol_data),
            patch(
                'src.redemptions.graph.graph_client.fetch_pages',
                side_effect=[allocators, leverage_positions, os_token_holders],
            ),
            patch_ipfs_client() as mock_upload_json,
        ):
            result = runner.invoke(update_redeemable_positions, args, input='\n')
            assert result.exit_code == 0
            mock_upload_json.assert_called_once_with(
                [{'owner': address_1, 'vault': vault_1, 'amount': '10000000000000000000'}]
            )
            assert (
                '0x9b4419ebea301ed07e591b477e69499f35e4c3cd69538c2f22a6a014b06e5bbd'
                in result.output.strip()
            )

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_min_os_token_position_amount(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        # hardcoded to check merkle root
        address_1 = '0x2242b8ab71521f6abEE4B4D83195E70AcB08727a'
        vault_1 = '0xEd735de172272C03CA6F60c1d90D83D9CFB46D22'
        allocators = [
            {
                'vault': {
                    'id': vault_1.lower(),
                },
                'id': address_1.lower(),
                'address': address_1,
                'mintedOsTokenShares': Web3.to_wei(5, 'ether'),
            },
        ]
        leverage_positions = []
        os_token_holders = []
        mock_protocol_data = []
        os_token_converter = OsTokenConverter(110, 100)
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--arbitrum-endpoint',
            execution_endpoints,
            '--verbose',
            '--min-os-token-position-amount-gwei',
            6 * 10**9,  # 6 ETH in Gwei
        ]
        with (
            patch_latest_block(11),
            patch_get_erc_balance(Web3.to_wei(0, 'ether')),
            patch_os_token_redeemer_contract_nonce(6),
            patch_os_token_arbitrum_contract_address(),
            patch_os_token_contract_address(os_token_contract_address),
            patch_os_token_converter(os_token_converter),
            patch_api_client(mock_protocol_data),
            patch(
                'src.redemptions.graph.graph_client.fetch_pages',
                side_effect=[allocators, leverage_positions, os_token_holders],
            ),
            patch_ipfs_client() as mock_upload_json,
        ):
            result = runner.invoke(update_redeemable_positions, args, input='\n')
            assert result.exit_code == 0
            mock_upload_json.assert_not_called()

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_min_os_token_position_amount_after_kept_shares(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        # hardcoded to check merkle root
        address_1 = '0x2242b8ab71521f6abEE4B4D83195E70AcB08727a'
        vault_1 = '0xEd735de172272C03CA6F60c1d90D83D9CFB46D22'
        allocators = [
            {
                'vault': {
                    'id': vault_1.lower(),
                },
                'id': address_1.lower(),
                'address': address_1,
                'mintedOsTokenShares': Web3.to_wei(10, 'ether'),
            },
        ]
        leverage_positions = []
        os_token_holders = [
            {
                'id': address_1.lower(),
                'balance': Web3.to_wei(7, 'ether'),
            },
        ]
        mock_protocol_data = []
        os_token_converter = OsTokenConverter(110, 100)
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--arbitrum-endpoint',
            execution_endpoints,
            '--verbose',
            '--min-os-token-position-amount-gwei',
            6 * 10**9,  # 6 ETH in Gwei
        ]
        with (
            patch_latest_block(11),
            patch_get_erc_balance(Web3.to_wei(0, 'ether')),
            patch_os_token_redeemer_contract_nonce(6),
            patch_os_token_arbitrum_contract_address(),
            patch_os_token_contract_address(os_token_contract_address),
            patch_os_token_converter(os_token_converter),
            patch_api_client(mock_protocol_data),
            patch(
                'src.redemptions.graph.graph_client.fetch_pages',
                side_effect=[allocators, leverage_positions, os_token_holders],
            ),
            patch_ipfs_client() as mock_upload_json,
        ):
            result = runner.invoke(update_redeemable_positions, args, input='\n')
            assert result.exit_code == 0
            mock_upload_json.assert_not_called()


@contextlib.contextmanager
def patch_latest_block(block_number):
    with patch(
        'src.commands.internal.update_redeemable_positions.execution_client', new=AsyncMock()
    ) as execution_client_mock:
        execution_client_mock.eth.get_block_number.return_value = block_number
        yield


@contextlib.contextmanager
def patch_os_token_converter(os_token_converter: OsTokenConverter):
    with patch(
        'src.commands.internal.update_redeemable_positions.create_os_token_converter',
        return_value=os_token_converter,
    ):
        yield


@contextlib.contextmanager
def patch_get_erc_balance(balance):
    with patch(
        'src.commands.internal.update_redeemable_positions.Erc20Contract.get_balance',
        return_value=balance,
    ):
        yield


@contextlib.contextmanager
def patch_os_token_arbitrum_contract_address():
    with patch.object(
        settings.network_config,
        'OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS',
        NETWORKS[MAINNET].OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS,
    ):
        yield


@contextlib.contextmanager
def patch_os_token_contract_address(address: ChecksumAddress):
    with patch.object(
        settings.network_config,
        'OS_TOKEN_CONTRACT_ADDRESS',
        address,
    ):
        yield


@contextlib.contextmanager
def patch_os_token_redeemer_contract_nonce(nonce):
    with patch(
        'src.commands.internal.update_redeemable_positions.os_token_redeemer_contract.nonce',
        return_value=nonce,
    ):
        yield


@contextlib.contextmanager
def patch_api_client(mock_protocol_data):
    with patch('src.redemptions.api_client.APIClient._fetch_json', return_value=mock_protocol_data):
        yield


@contextlib.contextmanager
def patch_ipfs_client():
    mock_upload_json = AsyncMock(return_value=faker.ipfs_hash())
    mock_ipfs_client = MagicMock()
    mock_ipfs_client.upload_json = mock_upload_json
    mock_build = MagicMock(return_value=mock_ipfs_client)
    with patch(
        'src.commands.internal.update_redeemable_positions.build_ipfs_upload_clients', mock_build
    ):
        yield mock_upload_json
