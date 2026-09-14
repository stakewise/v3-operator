import contextlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner
from sw_utils import OsTokenConverter
from sw_utils.tests import faker
from web3 import Web3
from web3.types import ChecksumAddress, Wei

from src.config.networks import MAINNET, NETWORKS
from src.config.settings import settings
from src.redemptions.commands.fetch_redeemable_positions import (
    _distribute_boosted_shares,
    _filter_min_redeemable_shares,
    _filter_min_vault_slices,
    calculate_boost_os_token_shares,
    fetch_redeemable_positions,
)
from src.redemptions.typings import (
    Allocator,
    LeverageStrategyPosition,
    VaultOsTokenPosition,
)

os_token_contract_address = NETWORKS[MAINNET].OS_TOKEN_CONTRACT_ADDRESS


def test_filter_min_redeemable_shares_drops_allocators_left_with_no_positions():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()

    allocator_a = Allocator(
        address=Web3.to_checksum_address(address_1),
        vault_os_token_positions=[
            VaultOsTokenPosition(
                address=Web3.to_checksum_address(vault_1), minted_shares=Wei(500), ltv=0.5
            ),
            VaultOsTokenPosition(
                address=Web3.to_checksum_address(vault_2), minted_shares=Wei(100), ltv=0.5
            ),
        ],
    )
    allocator_b = Allocator(
        address=Web3.to_checksum_address(address_2),
        vault_os_token_positions=[
            VaultOsTokenPosition(
                address=Web3.to_checksum_address(vault_1), minted_shares=Wei(50), ltv=0.5
            ),
        ],
    )

    result = _filter_min_redeemable_shares([allocator_a, allocator_b], Wei(200))
    assert result == [allocator_a]
    assert result[0].vault_os_token_positions == [
        VaultOsTokenPosition(
            address=Web3.to_checksum_address(vault_1), minted_shares=Wei(500), ltv=0.5
        ),
    ]


def test_filter_min_redeemable_shares_zero_threshold_keeps_everything():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(0), ltv=0.5
                ),
            ],
        ),
    ]

    result = _filter_min_redeemable_shares(allocators, Wei(0))
    assert result == allocators


def test_filter_min_vault_slices_drops_allocators_covered_by_kept_shares():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()

    # fully covered by locked shares -> no vault slice survives
    allocator_a = Allocator(
        address=Web3.to_checksum_address(address_1),
        vault_os_token_positions=[
            VaultOsTokenPosition(
                address=Web3.to_checksum_address(vault_1), minted_shares=Wei(500), ltv=0.5
            ),
        ],
        locked_shares=Wei(500),
    )
    # a slice above the threshold survives
    allocator_b = Allocator(
        address=Web3.to_checksum_address(address_2),
        vault_os_token_positions=[
            VaultOsTokenPosition(
                address=Web3.to_checksum_address(vault_1), minted_shares=Wei(500), ltv=0.5
            ),
        ],
        locked_shares=Wei(100),
    )

    result = _filter_min_vault_slices([allocator_a, allocator_b], Wei(200))
    assert result == [allocator_b]


def test_filter_min_vault_slices_zero_threshold_drops_only_zero_redeemable():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()

    # fully covered by locked shares -> zero redeemable, dropped even with zero threshold
    allocator_a = Allocator(
        address=Web3.to_checksum_address(address_1),
        vault_os_token_positions=[
            VaultOsTokenPosition(
                address=Web3.to_checksum_address(vault_1), minted_shares=Wei(500), ltv=0.5
            ),
        ],
        locked_shares=Wei(500),
    )
    # any positive redeemable amount is kept when the threshold is zero
    allocator_b = Allocator(
        address=Web3.to_checksum_address(address_2),
        vault_os_token_positions=[
            VaultOsTokenPosition(
                address=Web3.to_checksum_address(vault_1), minted_shares=Wei(500), ltv=0.5
            ),
        ],
        locked_shares=Wei(1),
    )

    result = _filter_min_vault_slices([allocator_a, allocator_b], Wei(0))
    assert result == [allocator_b]


async def test_calculate_boost_os_token_shares():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    proxy = faker.eth_address()

    os_token_converter = OsTokenConverter(105, 100)

    # empty case
    result = await calculate_boost_os_token_shares(set(), [], os_token_converter)
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
    result = await calculate_boost_os_token_shares(
        {address_1, address_2}, leverage_positions, os_token_converter
    )
    assert result == {
        (address_1, vault_1): 3570,
        (address_2, vault_1): 100,
        (address_2, vault_2): 3095,
    }


def test_distributes_boosted_shares():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    # empty case
    allocators = [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000), ltv=0.5),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(2000), ltv=0.5),
            ],
        )
    ]
    boost_ostoken_shares = {}
    _distribute_boosted_shares(allocators, boost_ostoken_shares)
    assert allocators == [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000), ltv=0.5),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(2000), ltv=0.5),
            ],
        )
    ]
    # basic reduction
    allocators = [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(500), ltv=0.5),
            ],
        ),
        Allocator(
            address=address_2,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000), ltv=0.5),
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(2000), ltv=0.5),
            ],
        ),
    ]
    boost_ostoken_shares = {
        (address_1, vault_1): Wei(300),
        (address_2, vault_1): Wei(500),
        (address_2, vault_2): Wei(1500),
    }

    _distribute_boosted_shares(allocators, boost_ostoken_shares)
    assert allocators == [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=vault_1, minted_shares=Wei(500), ltv=0.5, boosted_shares=Wei(300)
                ),
            ],
        ),
        Allocator(
            address=address_2,
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=vault_1, minted_shares=Wei(1000), ltv=0.5, boosted_shares=Wei(500)
                ),
                VaultOsTokenPosition(
                    address=vault_2, minted_shares=Wei(2000), ltv=0.5, boosted_shares=Wei(1500)
                ),
            ],
        ),
    ]
    assert [a.total_redeemable_shares for a in allocators] == [Wei(200), Wei(1000)]
    assert [a.residual_boosted_shares for a in allocators] == [Wei(0), Wei(0)]


def test_distributes_boosted_shares_cross_vault_residual():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()

    # boosted at vault_2, but the user only minted at vault_1: no same-vault mint to
    # match against, so the full boosted amount becomes a residual for the user.
    allocators = [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000), ltv=0.5),
            ],
        ),
    ]
    boost_ostoken_shares = {(address_1, vault_2): Wei(400)}

    _distribute_boosted_shares(allocators, boost_ostoken_shares)
    assert allocators == [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000), ltv=0.5),
            ],
            residual_boosted_shares=Wei(400),
        ),
    ]


def test_distributes_boosted_shares_excess_over_same_vault_mint_becomes_residual():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()

    # boosted amount exceeds the same-vault mint: match what fits, carry the rest as residual.
    allocators = [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(300), ltv=0.5),
            ],
        ),
    ]
    boost_ostoken_shares = {(address_1, vault_1): Wei(500)}

    _distribute_boosted_shares(allocators, boost_ostoken_shares)
    assert allocators == [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=vault_1, minted_shares=Wei(300), ltv=0.5, boosted_shares=Wei(300)
                ),
            ],
            residual_boosted_shares=Wei(200),
        ),
    ]
    assert allocators[0].total_redeemable_shares == Wei(0)
    assert allocators[0].residual_boosted_shares == Wei(200)


@pytest.mark.usefixtures('_init_config')
class TestFetchRedeemablePositions:
    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_basic_call_writes_snapshot(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        vault_1 = Web3.to_checksum_address('0xEd735de172272C03CA6F60c1d90D83D9CFB46D22')
        allocators = [
            Allocator(
                address=address_1,
                vault_os_token_positions=[
                    VaultOsTokenPosition(
                        address=vault_1, minted_shares=Web3.to_wei(10, 'ether'), ltv=0.5
                    ),
                ],
            ),
        ]
        leverage_positions: list[LeverageStrategyPosition] = []
        os_token_holders = {address_1: Web3.to_wei(4, 'ether')}
        mock_protocol_data = [
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
        ]
        os_token_converter = OsTokenConverter(110, 100)
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
        ]
        with (
            patch_finalized_block(11),
            patch_os_token_contract_address(os_token_contract_address),
            patch_os_token_converter(os_token_converter),
            patch_api_client(mock_protocol_data),
            patch_graph_calls(allocators, leverage_positions, os_token_holders),
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            result = runner.invoke(fetch_redeemable_positions, args, input='\n')
            assert result.exit_code == 0
            assert 'Fetching redeemable positions at block: 11' in result.output

            snapshot_file = Path('redeemable_allocators_11.json')
            assert snapshot_file.exists()
            assert f'Redeemable allocators saved to {snapshot_file}' in result.output

            with open(snapshot_file, encoding='utf-8') as f:
                data = json.load(f)

            assert data['block_number'] == 11
            assert data['min_os_token_position_amount_gwei'] == 0
            assert len(data['allocators']) == 1
            allocator_data = data['allocators'][0]
            assert allocator_data['address'] == address_1
            assert allocator_data['wallet_shares'] == str(Web3.to_wei(4, 'ether'))
            assert allocator_data['locked_shares'] == str(Web3.to_wei(2, 'ether'))
            assert allocator_data['vault_os_token_positions'] == [
                {
                    'vault': vault_1,
                    'minted_shares': str(Web3.to_wei(10, 'ether')),
                    'boosted_shares': '0',
                    'ltv': 0.5,
                }
            ]

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_cross_vault_boost_reduces_redeemable_amount(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        vault_1 = Web3.to_checksum_address('0xEd735de172272C03CA6F60c1d90D83D9CFB46D22')
        vault_2 = Web3.to_checksum_address('0xe8Ea1025b49D2B51C536cFBc0833F021ba4c6903')
        allocators = [
            Allocator(
                address=address_1,
                vault_os_token_positions=[
                    VaultOsTokenPosition(
                        address=vault_1, minted_shares=Web3.to_wei(10, 'ether'), ltv=0.5
                    ),
                ],
            ),
        ]
        # boosted into a leverage strategy keyed to vault_2, where the user never minted
        leverage_positions = [
            LeverageStrategyPosition(
                user=address_1,
                vault=vault_2,
                proxy=Web3.to_checksum_address(faker.eth_address()),
                os_token_shares=Web3.to_wei(3, 'ether'),
                exiting_os_token_shares=Wei(0),
                assets=Wei(0),
                exiting_assets=Wei(0),
            ),
        ]
        os_token_holders: dict[ChecksumAddress, Wei] = {}
        mock_protocol_data = []
        os_token_converter = OsTokenConverter(110, 100)
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
        ]
        with (
            patch_finalized_block(11),
            patch_os_token_contract_address(os_token_contract_address),
            patch_os_token_converter(os_token_converter),
            patch_api_client(mock_protocol_data),
            patch_graph_calls(allocators, leverage_positions, os_token_holders),
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            result = runner.invoke(fetch_redeemable_positions, args, input='\n')
            assert result.exit_code == 0

            with open('redeemable_allocators_11.json', encoding='utf-8') as f:
                data = json.load(f)

            allocator_data = data['allocators'][0]
            assert allocator_data['residual_boosted_shares'] == str(Web3.to_wei(3, 'ether'))
            assert allocator_data['vault_os_token_positions'][0]['boosted_shares'] == '0'

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_min_leaf_shares_writes_empty_snapshot(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        vault_1 = Web3.to_checksum_address('0xEd735de172272C03CA6F60c1d90D83D9CFB46D22')
        allocators = [
            Allocator(
                address=address_1,
                vault_os_token_positions=[
                    VaultOsTokenPosition(
                        address=vault_1, minted_shares=Web3.to_wei(5, 'ether'), ltv=0.5
                    ),
                ],
            ),
        ]
        leverage_positions: list[LeverageStrategyPosition] = []
        os_token_holders: dict[ChecksumAddress, Wei] = {}
        mock_protocol_data = []
        os_token_converter = OsTokenConverter(110, 100)
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
            '--min-os-token-position-amount-gwei',
            6 * 10**9,  # 6 ETH in Gwei
        ]
        with (
            patch_finalized_block(11),
            patch_os_token_contract_address(os_token_contract_address),
            patch_os_token_converter(os_token_converter),
            patch_api_client(mock_protocol_data),
            patch_graph_calls(allocators, leverage_positions, os_token_holders),
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            result = runner.invoke(fetch_redeemable_positions, args, input='\n')
            assert result.exit_code == 0

            with open('redeemable_allocators_11.json', encoding='utf-8') as f:
                data = json.load(f)

            assert data['allocators'] == []
            assert data['min_os_token_position_amount_gwei'] == 6 * 10**9


@contextlib.contextmanager
def patch_graph_calls(
    allocators: list[Allocator],
    leverage_positions: list[LeverageStrategyPosition],
    os_token_holders: dict[ChecksumAddress, Wei],
):
    target = 'src.redemptions.commands.fetch_redeemable_positions'
    with (
        patch(f'{target}.graph_get_redeemable_allocators', return_value=allocators),
        patch(f'{target}.graph_get_leverage_positions', return_value=leverage_positions),
        patch(f'{target}.graph_get_os_token_holders', return_value=os_token_holders),
    ):
        yield


@contextlib.contextmanager
def patch_finalized_block(block_number: int):
    with patch(
        'src.redemptions.commands.fetch_redeemable_positions.execution_client', new=AsyncMock()
    ) as execution_client_mock:
        execution_client_mock.eth.get_block.return_value = {'number': block_number}
        yield


@contextlib.contextmanager
def patch_os_token_converter(os_token_converter: OsTokenConverter):
    with patch(
        'src.redemptions.commands.fetch_redeemable_positions.create_os_token_converter',
        return_value=os_token_converter,
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
def patch_api_client(mock_protocol_data):
    with patch('src.redemptions.api_client.APIClient._fetch_json', return_value=mock_protocol_data):
        yield


@contextlib.contextmanager
def patch_startup_check():
    with patch(
        'src.redemptions.commands.fetch_redeemable_positions._startup_check',
        new=AsyncMock(),
    ):
        yield
