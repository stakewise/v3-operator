import contextlib
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from click.testing import CliRunner
from sw_utils.tests import faker
from web3.types import Wei

from src.config.networks import MAINNET
from src.redemptions.commands.publish_redeemable_positions import (
    publish_redeemable_positions,
)
from src.redemptions.merkle_tree import PositionsMerkleTree
from src.redemptions.typings import OsTokenPosition

NONCE = 6


@pytest.mark.usefixtures('fake_settings')
class TestPublishRedeemablePositions:
    async def test_publishes_positions(
        self, runner: CliRunner, execution_endpoints: str, tmp_path: Path
    ):
        payload = _build_payload(3)
        positions_file = _write_positions_file(tmp_path, payload)
        positions = [OsTokenPosition.from_dict(item) for item in payload]
        expected_root = PositionsMerkleTree(positions, leaf_nonce=NONCE).root

        with _patch_nonce(NONCE), _patch_ipfs_client() as mock_upload_json, _patch_startup_check():
            result = runner.invoke(
                publish_redeemable_positions,
                _build_args(positions_file, execution_endpoints),
            )

        assert result.exit_code == 0, result.output
        assert expected_root in result.output
        mock_upload_json.assert_called_once_with([position.as_dict() for position in positions])

    async def test_uploaded_payload_is_normalized(
        self, runner: CliRunner, execution_endpoints: str, tmp_path: Path
    ):
        owner = faker.eth_address()
        vault = faker.eth_address()
        positions_file = _write_positions_file(
            tmp_path, [{'owner': owner.lower(), 'vault': vault.lower(), 'leaf_shares': 10}]
        )

        with _patch_nonce(NONCE), _patch_ipfs_client() as mock_upload_json, _patch_startup_check():
            result = runner.invoke(
                publish_redeemable_positions,
                _build_args(positions_file, execution_endpoints),
            )

        assert result.exit_code == 0, result.output
        mock_upload_json.assert_called_once_with(
            [{'owner': owner, 'vault': vault, 'leaf_shares': '10'}]
        )

    async def test_dry_run_skips_upload(
        self, runner: CliRunner, execution_endpoints: str, tmp_path: Path
    ):
        payload = _build_payload(2)
        positions_file = _write_positions_file(tmp_path, payload)
        positions = [OsTokenPosition.from_dict(item) for item in payload]
        expected_root = PositionsMerkleTree(positions, leaf_nonce=NONCE).root

        with (
            _patch_nonce(NONCE),
            _patch_ipfs_client() as mock_upload_json,
            _patch_startup_check(),
        ):
            result = runner.invoke(
                publish_redeemable_positions,
                [*_build_args(positions_file, execution_endpoints), '--dry-run'],
            )

        assert result.exit_code == 0, result.output
        assert expected_root in result.output
        mock_upload_json.assert_not_called()

    async def test_rejects_duplicate_positions(
        self, runner: CliRunner, execution_endpoints: str, tmp_path: Path
    ):
        payload = _build_payload(2)
        duplicate = {**payload[0], 'leaf_shares': '999'}
        positions_file = _write_positions_file(tmp_path, [*payload, duplicate])

        with _patch_nonce(NONCE), _patch_ipfs_client() as mock_upload_json, _patch_startup_check():
            result = runner.invoke(
                publish_redeemable_positions,
                _build_args(positions_file, execution_endpoints),
            )

        assert result.exit_code != 0
        assert 'Duplicate position' in result.output
        mock_upload_json.assert_not_called()

    async def test_rejects_empty_list(
        self, runner: CliRunner, execution_endpoints: str, tmp_path: Path
    ):
        positions_file = _write_positions_file(tmp_path, [])

        with _patch_nonce(NONCE), _patch_ipfs_client() as mock_upload_json, _patch_startup_check():
            result = runner.invoke(
                publish_redeemable_positions,
                _build_args(positions_file, execution_endpoints),
            )

        assert result.exit_code != 0
        assert 'No positions found' in result.output
        mock_upload_json.assert_not_called()

    async def test_rejects_malformed_positions(
        self, runner: CliRunner, execution_endpoints: str, tmp_path: Path
    ):
        positions_file = _write_positions_file(tmp_path, [{'owner': faker.eth_address()}])

        with _patch_nonce(NONCE), _patch_ipfs_client() as mock_upload_json, _patch_startup_check():
            result = runner.invoke(
                publish_redeemable_positions,
                _build_args(positions_file, execution_endpoints),
            )

        assert result.exit_code != 0
        assert 'Invalid positions file' in result.output
        mock_upload_json.assert_not_called()


def _build_payload(count: int) -> list[dict]:
    return [
        OsTokenPosition(
            owner=faker.eth_address(),
            vault=faker.eth_address(),
            leaf_shares=Wei(faker.random_int(min=1, max=10**18)),
        ).as_dict()
        for _ in range(count)
    ]


def _write_positions_file(directory: Path, payload: list) -> Path:
    positions_file = directory / 'redeemable_positions.json'
    positions_file.write_text(json.dumps(payload), encoding='utf-8')
    return positions_file


def _build_args(positions_file: Path, execution_endpoints: str) -> list[str]:
    return [
        '--positions-file',
        str(positions_file),
        '--network',
        MAINNET,
        '--execution-endpoints',
        execution_endpoints,
        '--verbose',
    ]


@contextlib.contextmanager
def _patch_nonce(nonce: int):
    with patch(
        'src.redemptions.commands.update_redeemable_positions.os_token_redeemer_contract.nonce',
        return_value=nonce,
    ):
        yield


@contextlib.contextmanager
def _patch_ipfs_client():
    mock_upload_json = AsyncMock(return_value=faker.ipfs_hash())
    mock_ipfs_client = MagicMock()
    mock_ipfs_client.upload_json = mock_upload_json
    with patch(
        'src.redemptions.commands.update_redeemable_positions.build_ipfs_upload_clients',
        MagicMock(return_value=mock_ipfs_client),
    ):
        yield mock_upload_json


@contextlib.contextmanager
def _patch_startup_check():
    with patch(
        'src.redemptions.commands.publish_redeemable_positions._startup_check',
        new=AsyncMock(),
    ):
        yield
