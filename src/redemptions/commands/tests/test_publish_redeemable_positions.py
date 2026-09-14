import contextlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from eth_typing import BlockNumber
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Gwei, Wei

from src.config.networks import MAINNET
from src.redemptions.commands.publish_redeemable_positions import (
    _refresh_ltv,
    create_os_token_positions,
    publish_redeemable_positions,
)
from src.redemptions.typings import (
    Allocator,
    AllocatorsSnapshot,
    OsTokenPosition,
    VaultOsTokenPosition,
)


def test_create_os_token_positions_zero_allocators():
    result = create_os_token_positions([], Wei(0))
    assert result == []


def test_create_os_token_positions_single_vault():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150), ltv=0.5
                ),
            ],
        )
    ]
    result = create_os_token_positions(allocators, Wei(0))
    assert result == [OsTokenPosition(owner=address_1, vault=vault_1, leaf_shares=Wei(150))]


def test_create_os_token_positions_kept_tokens():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150), ltv=0.5
                ),
            ],
            wallet_shares=Wei(100),
        )
    ]
    result = create_os_token_positions(allocators, Wei(0))
    assert result == [OsTokenPosition(owner=address_1, vault=vault_1, leaf_shares=Wei(50))]


def test_create_os_token_positions_multiple_allocators():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    vault_1 = faker.eth_address()

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150), ltv=0.5
                ),
            ],
        ),
        Allocator(
            address=Web3.to_checksum_address(address_2),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(75), ltv=0.5
                ),
            ],
            wallet_shares=Wei(75),
        ),
    ]
    result = create_os_token_positions(allocators, Wei(0))
    assert result == [OsTokenPosition(owner=address_1, vault=vault_1, leaf_shares=Wei(150))]


def test_create_os_token_positions_multiple_vaults_1():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(150), ltv=0.5
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(150), ltv=0.5
                ),
            ],
        )
    ]
    result = create_os_token_positions(allocators, Wei(0))
    assert result == [
        OsTokenPosition(owner=address_1, vault=vault_1, leaf_shares=Wei(150)),
        OsTokenPosition(owner=address_1, vault=vault_2, leaf_shares=Wei(150)),
    ]


def test_create_os_token_positions_multiple_vaults_2():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(333), ltv=0.5
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(666), ltv=0.5
                ),
            ],
            wallet_shares=Wei(100),
        )
    ]
    result = create_os_token_positions(allocators, Wei(0))
    assert result == [
        OsTokenPosition(owner=address_1, vault=vault_2, leaf_shares=Wei(600)),
        OsTokenPosition(owner=address_1, vault=vault_1, leaf_shares=Wei(299)),
    ]


def test_create_os_token_positions_multiple_vaults_3():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(1), ltv=0.5
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(999), ltv=0.5
                ),
            ],
            wallet_shares=Wei(100),
        )
    ]
    result = create_os_token_positions(allocators, Wei(0))
    assert result == [
        OsTokenPosition(owner=address_1, vault=vault_2, leaf_shares=Wei(900)),
        OsTokenPosition(owner=address_1, vault=vault_1, leaf_shares=Wei(0)),
    ]


def test_create_os_token_positions_min_redeemable_shares():
    address_1 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()
    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(333), ltv=0.5
                ),
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(666), ltv=0.5
                ),
            ],
            wallet_shares=Wei(100),
        )
    ]
    result = create_os_token_positions(allocators, Wei(300))
    assert result == [
        OsTokenPosition(owner=address_1, vault=vault_2, leaf_shares=Wei(600)),
    ]


def test_create_os_token_positions_ordering_by_ltv_and_amount():
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()
    address_3 = faker.eth_address()
    vault_1 = faker.eth_address()
    vault_2 = faker.eth_address()

    allocators = [
        Allocator(
            address=Web3.to_checksum_address(address_1),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(1000), ltv=0.3
                ),
            ],
        ),
        Allocator(
            address=Web3.to_checksum_address(address_2),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_1), minted_shares=Wei(500), ltv=0.9
                ),
            ],
        ),
        Allocator(
            address=Web3.to_checksum_address(address_3),
            vault_os_token_positions=[
                VaultOsTokenPosition(
                    address=Web3.to_checksum_address(vault_2), minted_shares=Wei(200), ltv=0.9
                ),
            ],
        ),
    ]
    result = create_os_token_positions(allocators, Wei(0))
    # sorted by ltv desc, then amount desc
    assert result == [
        OsTokenPosition(owner=address_2, vault=vault_1, leaf_shares=Wei(500)),
        OsTokenPosition(owner=address_3, vault=vault_2, leaf_shares=Wei(200)),
        OsTokenPosition(owner=address_1, vault=vault_1, leaf_shares=Wei(1000)),
    ]


async def test_refresh_ltv_updates_found_and_keeps_missing_positions():
    address_1 = Web3.to_checksum_address(faker.eth_address())
    vault_1 = Web3.to_checksum_address(faker.eth_address())
    vault_2 = Web3.to_checksum_address(faker.eth_address())
    allocators = [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000), ltv=0.5),
                # not present in the current subgraph snapshot (e.g. fully redeemed since)
                VaultOsTokenPosition(address=vault_2, minted_shares=Wei(500), ltv=0.3),
            ],
        ),
    ]
    current_allocators = [
        Allocator(
            address=address_1,
            vault_os_token_positions=[
                VaultOsTokenPosition(address=vault_1, minted_shares=Wei(1000), ltv=0.9),
            ],
        ),
    ]

    with patch(
        'src.redemptions.commands.publish_redeemable_positions.graph_get_redeemable_allocators',
        return_value=current_allocators,
    ):
        await _refresh_ltv(allocators, BlockNumber(20))

    assert allocators[0].vault_os_token_positions[0].ltv == 0.9
    assert allocators[0].vault_os_token_positions[1].ltv == 0.3


@pytest.mark.usefixtures('_init_config')
class TestPublishRedeemablePositions:
    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_publish_uploads_positions(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        vault_1 = Web3.to_checksum_address('0xEd735de172272C03CA6F60c1d90D83D9CFB46D22')
        snapshot = AllocatorsSnapshot(
            block_number=BlockNumber(11),
            min_os_token_position_amount_gwei=Gwei(0),
            allocators=[
                Allocator(
                    address=address_1,
                    vault_os_token_positions=[
                        VaultOsTokenPosition(
                            address=vault_1, minted_shares=Web3.to_wei(10, 'ether'), ltv=0.5
                        ),
                    ],
                ),
            ],
        )
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
        ]
        with (
            patch_os_token_redeemer_contract_nonce(6),
            patch_graph_get_redeemable_allocators(snapshot.allocators),
            patch_ipfs_client() as mock_upload_json,
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            snapshot_file = Path('redeemable_allocators_11.json')
            with open(snapshot_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot.as_dict(), f)

            result = runner.invoke(
                publish_redeemable_positions,
                args + ['--allocators-file', str(snapshot_file)],
                input='\n',
            )
            assert result.exit_code == 0
            assert 'Positions fetched at block: 11' in result.output
            assert 'Generated Merkle Tree root:' in result.output
            mock_upload_json.assert_called_once_with(
                [
                    {
                        'owner': address_1,
                        'vault': vault_1,
                        'leaf_shares': str(Web3.to_wei(10, 'ether')),
                    }
                ]
            )

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_publish_skips_upload_when_no_redeemable_positions(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        # wallet already holds enough to cover the whole minted amount, so after refreshing
        # LTVs there is nothing left to redeem
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        vault_1 = Web3.to_checksum_address('0xEd735de172272C03CA6F60c1d90D83D9CFB46D22')
        snapshot = AllocatorsSnapshot(
            block_number=BlockNumber(11),
            min_os_token_position_amount_gwei=Gwei(0),
            allocators=[
                Allocator(
                    address=address_1,
                    vault_os_token_positions=[
                        VaultOsTokenPosition(
                            address=vault_1, minted_shares=Web3.to_wei(10, 'ether'), ltv=0.5
                        ),
                    ],
                    wallet_shares=Web3.to_wei(10, 'ether'),
                ),
            ],
        )
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
        ]
        with (
            patch_graph_get_redeemable_allocators(snapshot.allocators),
            patch_ipfs_client() as mock_upload_json,
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            snapshot_file = Path('redeemable_allocators_11.json')
            with open(snapshot_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot.as_dict(), f)

            result = runner.invoke(
                publish_redeemable_positions,
                args + ['--allocators-file', str(snapshot_file)],
                input='\n',
            )
            assert result.exit_code == 0
            mock_upload_json.assert_not_called()


@contextlib.contextmanager
def patch_graph_get_redeemable_allocators(allocators: list[Allocator]):
    with patch(
        'src.redemptions.commands.publish_redeemable_positions.graph_get_redeemable_allocators',
        return_value=allocators,
    ) as mock_call:
        yield mock_call


@contextlib.contextmanager
def patch_os_token_redeemer_contract_nonce(nonce: int):
    with patch(
        'src.redemptions.commands.publish_redeemable_positions.os_token_redeemer_contract.nonce',
        return_value=nonce,
    ):
        yield


@contextlib.contextmanager
def patch_ipfs_client():
    mock_upload_json = AsyncMock(return_value=faker.ipfs_hash())
    mock_ipfs_client = MagicMock()
    mock_ipfs_client.upload_json = mock_upload_json
    mock_build = MagicMock(return_value=mock_ipfs_client)
    with patch(
        'src.redemptions.commands.publish_redeemable_positions.build_ipfs_upload_clients',
        mock_build,
    ):
        yield mock_upload_json


@contextlib.contextmanager
def patch_startup_check():
    with patch(
        'src.redemptions.commands.publish_redeemable_positions._startup_check',
        new=AsyncMock(),
    ):
        yield
