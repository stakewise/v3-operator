from pathlib import Path
from typing import Generator
from unittest import mock

import pytest
from click.testing import CliRunner

from src.common.tests.factories import create_chain_head
from src.config.networks import HOODI
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
