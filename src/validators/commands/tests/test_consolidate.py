from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner
from sw_utils.tests import faker

from src.config.networks import HOODI
from src.config.settings import DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI
from src.validators.commands.consolidate import consolidate


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
