from pathlib import Path
from typing import Generator
from unittest import mock
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner
from sw_utils.tests import faker

from src.common.tests.factories import create_chain_head
from src.config.networks import HOODI
from src.config.settings import DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI
from src.validators.commands.consolidate import consolidate
from src.validators.exceptions import ConsolidationError


@pytest.fixture
def _patch_check_validators_manager() -> Generator:
    with mock.patch(
        'src.validators.commands.consolidate.check_validators_manager',
        return_value=None,
    ):
        yield


@pytest.fixture
def _patch_check_consolidations_queue() -> Generator:
    with mock.patch(
        'src.validators.commands.consolidate._check_consolidations_queue',
        return_value=None,
    ):
        yield


@pytest.fixture
def _patch_get_chain_latest_head() -> Generator:
    with mock.patch(
        'src.validators.commands.consolidate.get_chain_latest_head',
        return_value=create_chain_head(),
    ):
        yield


@pytest.mark.usefixtures(
    '_patch_check_validators_manager',
    '_patch_check_consolidations_queue',
    '_patch_get_chain_latest_head',
)
class TestConsolidate:
    @pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
    def test_create_consolidation_error_is_wrapped_in_click_exception(
        self,
        vault_address: str,
        consensus_endpoints: str,
        execution_endpoints: str,
        data_dir: Path,
        runner: CliRunner,
    ):
        """`ConsolidationManager.create` can raise `ConsolidationError` (e.g. an in-flight
        pending consolidation with an unresolvable source balance); it must surface as a clean
        `click.ClickException`, not fall through to the generic verbose-error handler."""
        args = [
            '--vault',
            vault_address,
            '--network',
            HOODI,
            '--consensus-endpoints',
            consensus_endpoints,
            '--execution-endpoints',
            execution_endpoints,
            '--data-dir',
            str(data_dir),
            '--no-confirm',
        ]
        with mock.patch(
            'src.validators.commands.consolidate.ConsolidationManager'
        ) as consolidation_manager:
            consolidation_manager.create = mock.AsyncMock(
                side_effect=ConsolidationError('boom message')
            )
            result = runner.invoke(consolidate, args)

        assert result.exit_code != 0
        assert 'Error: boom message' in result.output


def test_empty_source_public_keys_file_raises(
    vault_address: str,
    consensus_endpoints: str,
    execution_endpoints: str,
    data_dir: Path,
    tmp_path: Path,
    runner: CliRunner,
):
    empty_source_public_keys_file = tmp_path / 'empty_source_public_keys.txt'
    empty_source_public_keys_file.touch()
    target_public_key = faker.validator_public_key()

    args = [
        '--vault',
        vault_address,
        '--network',
        HOODI,
        '--consensus-endpoints',
        consensus_endpoints,
        '--execution-endpoints',
        execution_endpoints,
        '--data-dir',
        str(data_dir),
        '--source-public-keys-file',
        str(empty_source_public_keys_file),
        '--target-public-key',
        target_public_key,
    ]
    with patch('src.validators.commands.consolidate.main', new_callable=AsyncMock) as mocked_main:
        result = runner.invoke(consolidate, args)
        mocked_main.assert_not_called()

    assert result.exit_code != 0
    assert f'No public keys found in {empty_source_public_keys_file}.' in result.output


def test_source_public_keys_file_with_keys_proceeds(
    vault_address: str,
    consensus_endpoints: str,
    execution_endpoints: str,
    data_dir: Path,
    tmp_path: Path,
    runner: CliRunner,
):
    source_public_keys = [faker.validator_public_key(), faker.validator_public_key()]
    source_public_keys_file = tmp_path / 'source_public_keys.txt'
    source_public_keys_file.write_text('\n'.join(source_public_keys) + '\n')
    target_public_key = faker.validator_public_key()

    args = [
        '--vault',
        vault_address,
        '--network',
        HOODI,
        '--consensus-endpoints',
        consensus_endpoints,
        '--execution-endpoints',
        execution_endpoints,
        '--data-dir',
        str(data_dir),
        '--source-public-keys-file',
        str(source_public_keys_file),
        '--target-public-key',
        target_public_key,
    ]
    with patch('src.validators.commands.consolidate.main', new_callable=AsyncMock) as mocked_main:
        result = runner.invoke(consolidate, args)
        mocked_main.assert_called_once_with(
            source_public_keys=source_public_keys,
            target_public_key=target_public_key,
            exclude_public_keys=set(),
            no_switch_consolidation=False,
            max_consolidation_request_fee_gwei=DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI,
            no_confirm=False,
        )

    assert result.exit_code == 0


def test_source_public_keys_file_blank_line_rejected_at_parse_time(
    vault_address: str,
    consensus_endpoints: str,
    execution_endpoints: str,
    data_dir: Path,
    tmp_path: Path,
    runner: CliRunner,
):
    blank_line_source_public_keys_file = tmp_path / 'blank_line_source_public_keys.txt'
    blank_line_source_public_keys_file.write_text('\n')
    target_public_key = faker.validator_public_key()

    args = [
        '--vault',
        vault_address,
        '--network',
        HOODI,
        '--consensus-endpoints',
        consensus_endpoints,
        '--execution-endpoints',
        execution_endpoints,
        '--data-dir',
        str(data_dir),
        '--source-public-keys-file',
        str(blank_line_source_public_keys_file),
        '--target-public-key',
        target_public_key,
    ]
    with patch('src.validators.commands.consolidate.main', new_callable=AsyncMock) as mocked_main:
        result = runner.invoke(consolidate, args)
        mocked_main.assert_not_called()

    assert result.exit_code != 0
    assert 'Invalid validator public key' in result.output


def test_empty_exclude_public_keys_file_raises(
    vault_address: str,
    consensus_endpoints: str,
    execution_endpoints: str,
    data_dir: Path,
    tmp_path: Path,
    runner: CliRunner,
):
    empty_exclude_public_keys_file = tmp_path / 'empty_exclude_public_keys.txt'
    empty_exclude_public_keys_file.touch()

    args = [
        '--vault',
        vault_address,
        '--network',
        HOODI,
        '--consensus-endpoints',
        consensus_endpoints,
        '--execution-endpoints',
        execution_endpoints,
        '--data-dir',
        str(data_dir),
        '--exclude-public-keys-file',
        str(empty_exclude_public_keys_file),
    ]
    with patch('src.validators.commands.consolidate.main', new_callable=AsyncMock) as mocked_main:
        result = runner.invoke(consolidate, args)
        mocked_main.assert_not_called()

    assert result.exit_code != 0
    assert f'No public keys found in {empty_exclude_public_keys_file}.' in result.output
