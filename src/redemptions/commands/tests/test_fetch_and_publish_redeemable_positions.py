"""
End-to-end coverage for the fetch-redeemable-positions -> publish-redeemable-positions
pipeline, chained together as they would be run in production. The hardcoded Merkle roots
and payloads mirror the ones the single update-redeemable-positions command used to produce,
since splitting the command did not change the underlying computation.
"""

import json

import pytest
from click.testing import CliRunner
from sw_utils import OsTokenConverter
from sw_utils.tests import faker
from web3 import Web3
from web3.types import ChecksumAddress, Wei

from src.config.networks import MAINNET, NETWORKS
from src.redemptions.commands.fetch_redeemable_positions import (
    fetch_redeemable_positions,
)
from src.redemptions.commands.publish_redeemable_positions import (
    publish_redeemable_positions,
)
from src.redemptions.commands.tests.test_fetch_redeemable_positions import (
    patch_api_client,
    patch_finalized_block,
    patch_graph_calls,
    patch_os_token_contract_address,
    patch_os_token_converter,
)
from src.redemptions.commands.tests.test_fetch_redeemable_positions import (
    patch_startup_check as patch_fetch_startup_check,
)
from src.redemptions.commands.tests.test_publish_redeemable_positions import (
    patch_ipfs_client,
    patch_os_token_redeemer_contract_nonce,
)
from src.redemptions.commands.tests.test_publish_redeemable_positions import (
    patch_startup_check as patch_publish_startup_check,
)
from src.redemptions.typings import (
    Allocator,
    LeverageStrategyPosition,
    VaultOsTokenPosition,
)

os_token_contract_address = NETWORKS[MAINNET].OS_TOKEN_CONTRACT_ADDRESS


@pytest.mark.usefixtures('_init_config')
class TestFetchAndPublishRedeemablePositions:
    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_basic_call(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        # hardcoded to check merkle root
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        address_2 = Web3.to_checksum_address('0x24c8DBBC3d1C35C4159787b1f7a62bea1A814242')
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
            Allocator(
                address=address_2,
                vault_os_token_positions=[
                    VaultOsTokenPosition(
                        address=vault_2, minted_shares=Web3.to_wei(12, 'ether'), ltv=0.5
                    ),
                ],
            ),
        ]
        leverage_positions = [
            LeverageStrategyPosition(
                user=address_1,
                vault=vault_1,
                proxy=Web3.to_checksum_address(faker.eth_address()),
                os_token_shares=Web3.to_wei(1, 'ether'),
                exiting_os_token_shares=Web3.to_wei(0.1, 'ether'),
                assets=Web3.to_wei(0.1, 'ether'),
                exiting_assets=Web3.to_wei(0.05, 'ether'),
            ),
        ]
        os_token_holders = {
            address_1: Web3.to_wei(4, 'ether'),
            address_2: Web3.to_wei(13, 'ether'),
        }
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

        fetch_and_publish(
            runner=runner,
            execution_endpoints=execution_endpoints,
            allocators=allocators,
            leverage_positions=leverage_positions,
            os_token_holders=os_token_holders,
            mock_protocol_data=mock_protocol_data,
            os_token_converter=os_token_converter,
            assert_result=lambda publish_result, mock_upload_json: (
                mock_upload_json.assert_called_once_with(
                    [
                        {
                            'owner': address_1,
                            'vault': vault_1,
                            'leaf_shares': '2563636363636363637',
                        }
                    ]
                ),
                assert_output_contains(
                    publish_result,
                    '0x9bb2ee30813b89e23e6bbfa1b78706c008f71489750571c81d3b33289647bec1',
                ),
            ),
        )

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_full_position(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        # hardcoded to check merkle root
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
        os_token_holders: dict[ChecksumAddress, Wei] = {}
        mock_protocol_data: list[dict] = []
        os_token_converter = OsTokenConverter(110, 100)

        fetch_and_publish(
            runner=runner,
            execution_endpoints=execution_endpoints,
            allocators=allocators,
            leverage_positions=leverage_positions,
            os_token_holders=os_token_holders,
            mock_protocol_data=mock_protocol_data,
            os_token_converter=os_token_converter,
            assert_result=lambda publish_result, mock_upload_json: (
                mock_upload_json.assert_called_once_with(
                    [
                        {
                            'owner': address_1,
                            'vault': vault_1,
                            'leaf_shares': '10000000000000000000',
                        }
                    ]
                ),
                assert_output_contains(
                    publish_result,
                    '0x9b4419ebea301ed07e591b477e69499f35e4c3cd69538c2f22a6a014b06e5bbd',
                ),
            ),
        )

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
        mock_protocol_data: list[dict] = []
        os_token_converter = OsTokenConverter(110, 100)

        fetch_and_publish(
            runner=runner,
            execution_endpoints=execution_endpoints,
            allocators=allocators,
            leverage_positions=leverage_positions,
            os_token_holders=os_token_holders,
            mock_protocol_data=mock_protocol_data,
            os_token_converter=os_token_converter,
            assert_result=lambda publish_result, mock_upload_json: (
                mock_upload_json.assert_called_once_with(
                    [
                        {
                            'owner': address_1,
                            'vault': vault_1,
                            'leaf_shares': '7000000000000000000',
                        }
                    ]
                )
            ),
        )

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_min_leaf_shares(
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
        mock_protocol_data: list[dict] = []
        os_token_converter = OsTokenConverter(110, 100)

        fetch_and_publish(
            runner=runner,
            execution_endpoints=execution_endpoints,
            allocators=allocators,
            leverage_positions=leverage_positions,
            os_token_holders=os_token_holders,
            mock_protocol_data=mock_protocol_data,
            os_token_converter=os_token_converter,
            min_os_token_position_amount_gwei=6 * 10**9,  # 6 ETH in Gwei
            assert_result=lambda publish_result, mock_upload_json: (
                mock_upload_json.assert_not_called()
            ),
        )

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_min_leaf_shares_after_kept_shares(
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
        os_token_holders = {address_1: Web3.to_wei(7, 'ether')}
        mock_protocol_data: list[dict] = []
        os_token_converter = OsTokenConverter(110, 100)

        fetch_and_publish(
            runner=runner,
            execution_endpoints=execution_endpoints,
            allocators=allocators,
            leverage_positions=leverage_positions,
            os_token_holders=os_token_holders,
            mock_protocol_data=mock_protocol_data,
            os_token_converter=os_token_converter,
            min_os_token_position_amount_gwei=6 * 10**9,  # 6 ETH in Gwei
            assert_result=lambda publish_result, mock_upload_json: (
                mock_upload_json.assert_not_called()
            ),
        )

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_hand_edited_positions_file_is_reflected_in_upload(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        """The positions file sits between the two commands as a plain, editable artifact:
        an operator may drop or shrink positions before publishing."""
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        address_2 = Web3.to_checksum_address('0x24c8DBBC3d1C35C4159787b1f7a62bea1A814242')
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
            Allocator(
                address=address_2,
                vault_os_token_positions=[
                    VaultOsTokenPosition(
                        address=vault_2, minted_shares=Web3.to_wei(12, 'ether'), ltv=0.9
                    ),
                ],
            ),
        ]
        leverage_positions: list[LeverageStrategyPosition] = []
        os_token_holders: dict[ChecksumAddress, Wei] = {}
        mock_protocol_data: list[dict] = []
        os_token_converter = OsTokenConverter(110, 100)

        fetch_args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
            '--min-os-token-position-amount-gwei',
            0,
        ]
        with (
            patch_finalized_block(11),
            patch_os_token_contract_address(os_token_contract_address),
            patch_os_token_converter(os_token_converter),
            patch_api_client(mock_protocol_data),
            patch_graph_calls(allocators, leverage_positions, os_token_holders),
            patch_fetch_startup_check(),
            runner.isolated_filesystem(),
        ):
            fetch_result = runner.invoke(fetch_redeemable_positions, fetch_args, input='\n')
            assert fetch_result.exit_code == 0

            positions_file = 'redeemable_positions_11.json'
            with open(positions_file, encoding='utf-8') as f:
                snapshot_data = json.load(f)

            assert len(snapshot_data['positions']) == 2
            # drop address_1's position entirely, and shrink address_2's leaf_shares
            snapshot_data['positions'] = [
                p for p in snapshot_data['positions'] if p['owner'] == address_2
            ]
            snapshot_data['positions'][0]['leaf_shares'] = str(Web3.to_wei(5, 'ether'))
            with open(positions_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot_data, f)

            publish_args = [
                '--network',
                MAINNET,
                '--execution-endpoints',
                execution_endpoints,
                '--verbose',
                '--positions-file',
                positions_file,
            ]
            with (
                patch_os_token_redeemer_contract_nonce(6),
                patch_ipfs_client() as mock_upload_json,
                patch_publish_startup_check(),
            ):
                publish_result = runner.invoke(
                    publish_redeemable_positions, publish_args, input='\n'
                )
                assert publish_result.exit_code == 0
                mock_upload_json.assert_called_once_with(
                    [
                        {
                            'owner': address_2,
                            'vault': vault_2,
                            'leaf_shares': str(Web3.to_wei(5, 'ether')),
                        }
                    ]
                )


def assert_output_contains(result, expected: str) -> None:
    assert expected in result.output.strip()


def fetch_and_publish(
    *,
    runner: CliRunner,
    execution_endpoints: str,
    allocators: list[Allocator],
    leverage_positions: list[LeverageStrategyPosition],
    os_token_holders: dict[ChecksumAddress, Wei],
    mock_protocol_data: list[dict],
    os_token_converter: OsTokenConverter,
    assert_result,
    min_os_token_position_amount_gwei: int = 0,
) -> None:
    fetch_args = [
        '--network',
        MAINNET,
        '--execution-endpoints',
        execution_endpoints,
        '--verbose',
        '--min-os-token-position-amount-gwei',
        min_os_token_position_amount_gwei,
    ]
    with (
        patch_finalized_block(11),
        patch_os_token_contract_address(os_token_contract_address),
        patch_os_token_converter(os_token_converter),
        patch_api_client(mock_protocol_data),
        patch_graph_calls(allocators, leverage_positions, os_token_holders),
        patch_fetch_startup_check(),
        runner.isolated_filesystem(),
    ):
        fetch_result = runner.invoke(fetch_redeemable_positions, fetch_args, input='\n')
        assert fetch_result.exit_code == 0

        publish_args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
            '--positions-file',
            'redeemable_positions_11.json',
        ]
        with (
            patch_os_token_redeemer_contract_nonce(6),
            patch_ipfs_client() as mock_upload_json,
            patch_publish_startup_check(),
        ):
            publish_result = runner.invoke(publish_redeemable_positions, publish_args, input='\n')
            assert publish_result.exit_code == 0
            assert_result(publish_result, mock_upload_json)
