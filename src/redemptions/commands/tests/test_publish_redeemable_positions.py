import contextlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from eth_typing import BlockNumber
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.config.networks import MAINNET
from src.redemptions.commands.publish_redeemable_positions import (
    publish_redeemable_positions,
)
from src.redemptions.typings import OsTokenPosition, RedeemablePositionsSnapshot


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
        snapshot = RedeemablePositionsSnapshot(
            block_number=BlockNumber(11),
            positions=[
                OsTokenPosition(
                    owner=address_1,
                    vault=vault_1,
                    leaf_shares=Web3.to_wei(10, 'ether'),
                    ltv=0.5,
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
            patch_ipfs_client() as mock_upload_json,
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            positions_file = Path('redeemable_positions_mainnet_11.json')
            with open(positions_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot.as_dict(), f)

            result = runner.invoke(
                publish_redeemable_positions,
                args + ['--positions-file', str(positions_file)],
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
        snapshot = RedeemablePositionsSnapshot(block_number=BlockNumber(11), positions=[])
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
        ]
        with (
            patch_ipfs_client() as mock_upload_json,
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            positions_file = Path('redeemable_positions_mainnet_11.json')
            with open(positions_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot.as_dict(), f)

            result = runner.invoke(
                publish_redeemable_positions,
                args + ['--positions-file', str(positions_file)],
                input='\n',
            )
            assert result.exit_code == 0
            mock_upload_json.assert_not_called()

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_publish_sorts_hand_edited_positions_by_ltv_desc(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        address_2 = Web3.to_checksum_address('0x24c8DBBC3d1C35C4159787b1f7a62bea1A814242')
        vault_1 = Web3.to_checksum_address('0xEd735de172272C03CA6F60c1d90D83D9CFB46D22')
        # positions saved out of ltv order, as if hand-edited after fetch
        snapshot = RedeemablePositionsSnapshot(
            block_number=BlockNumber(11),
            positions=[
                OsTokenPosition(
                    owner=address_1, vault=vault_1, leaf_shares=Web3.to_wei(1, 'ether'), ltv=0.3
                ),
                OsTokenPosition(
                    owner=address_2, vault=vault_1, leaf_shares=Web3.to_wei(2, 'ether'), ltv=0.9
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
            patch_ipfs_client() as mock_upload_json,
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            positions_file = Path('redeemable_positions_mainnet_11.json')
            with open(positions_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot.as_dict(), f)

            result = runner.invoke(
                publish_redeemable_positions,
                args + ['--positions-file', str(positions_file)],
                input='\n',
            )
            assert result.exit_code == 0
            mock_upload_json.assert_called_once_with(
                [
                    {
                        'owner': address_2,
                        'vault': vault_1,
                        'leaf_shares': str(Web3.to_wei(2, 'ether')),
                    },
                    {
                        'owner': address_1,
                        'vault': vault_1,
                        'leaf_shares': str(Web3.to_wei(1, 'ether')),
                    },
                ]
            )

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_publish_invalid_positions_file_exits_non_zero(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        args = [
            '--network',
            MAINNET,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
        ]
        with (
            patch_ipfs_client(),
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            positions_file = Path('redeemable_positions_mainnet_11.json')
            with open(positions_file, 'w', encoding='utf-8') as f:
                f.write('{not valid json')

            result = runner.invoke(
                publish_redeemable_positions,
                args + ['--positions-file', str(positions_file)],
                input='\n',
            )
            assert result.exit_code != 0
            assert f'Invalid positions file {positions_file}' in result.output

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_publish_non_positive_leaf_shares_exits_non_zero(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        vault_1 = Web3.to_checksum_address('0xEd735de172272C03CA6F60c1d90D83D9CFB46D22')
        snapshot = RedeemablePositionsSnapshot(
            block_number=BlockNumber(11),
            positions=[
                OsTokenPosition(
                    owner=address_1,
                    vault=vault_1,
                    leaf_shares=Wei(-1),
                    ltv=0.5,
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
            patch_ipfs_client() as mock_upload_json,
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            positions_file = Path('redeemable_positions_mainnet_11.json')
            with open(positions_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot.as_dict(), f)

            result = runner.invoke(
                publish_redeemable_positions,
                args + ['--positions-file', str(positions_file)],
                input='\n',
            )
            assert result.exit_code != 0
            assert 'Invalid positions file' in result.output
            mock_upload_json.assert_not_called()

    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    async def test_publish_duplicate_owner_vault_pair_exits_non_zero(
        self,
        vault_address: str,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        address_1 = Web3.to_checksum_address('0x2242b8ab71521f6abEE4B4D83195E70AcB08727a')
        vault_1 = Web3.to_checksum_address('0xEd735de172272C03CA6F60c1d90D83D9CFB46D22')
        snapshot = RedeemablePositionsSnapshot(
            block_number=BlockNumber(11),
            positions=[
                OsTokenPosition(
                    owner=address_1,
                    vault=vault_1,
                    leaf_shares=Web3.to_wei(1, 'ether'),
                    ltv=0.5,
                ),
                OsTokenPosition(
                    owner=address_1,
                    vault=vault_1,
                    leaf_shares=Web3.to_wei(2, 'ether'),
                    ltv=0.4,
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
            patch_ipfs_client() as mock_upload_json,
            patch_startup_check(),
            runner.isolated_filesystem(),
        ):
            positions_file = Path('redeemable_positions_mainnet_11.json')
            with open(positions_file, 'w', encoding='utf-8') as f:
                json.dump(snapshot.as_dict(), f)

            result = runner.invoke(
                publish_redeemable_positions,
                args + ['--positions-file', str(positions_file)],
                input='\n',
            )
            assert result.exit_code != 0
            assert 'Invalid positions file' in result.output
            mock_upload_json.assert_not_called()


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
