from pathlib import Path
from typing import Generator
from unittest import mock

import pytest
from click.testing import CliRunner
from sw_utils import ValidatorStatus

from src.commands.exit_validators import exit_validators
from src.common.tests.factories import create_chain_head
from src.validators.tests.factories import create_consensus_validator

DEFAULT_ACTIVATION_EPOCH = 10000
WITHDRAWAL_REQUEST_FEE = 2


@pytest.fixture
def _patch_check_vault_version() -> Generator:
    with mock.patch(
        'src.commands.exit_validators.check_vault_version',
        return_value=None,
    ):
        yield


@pytest.fixture
def _patch_check_validators_manager() -> Generator:
    with mock.patch(
        'src.commands.exit_validators.check_validators_manager',
        return_value=None,
    ):
        yield


@pytest.fixture
def _patch_get_execution_request_fee() -> Generator:
    with mock.patch(
        'src.commands.exit_validators.get_execution_request_fee',
        return_value=WITHDRAWAL_REQUEST_FEE,
    ):
        yield


@pytest.fixture
def _patch_submit_withdraw_validators() -> Generator:
    with mock.patch(
        'src.commands.exit_validators.submit_withdraw_validators',
        return_value=None,
    ):
        yield


@pytest.fixture
def _patch_get_chain_justified_head() -> Generator:
    with mock.patch(
        'src.commands.exit_validators.get_chain_justified_head',
        return_value=create_chain_head(epoch=DEFAULT_ACTIVATION_EPOCH),
    ):
        yield


@pytest.mark.usefixtures(
    '_patch_check_vault_version',
    '_patch_check_validators_manager',
    '_patch_get_execution_request_fee',
    '_patch_get_chain_justified_head',
)
@pytest.mark.usefixtures('_init_config')
class TestValidatorsExit:
    @pytest.mark.usefixtures('fake_settings')
    async def test_auto_exit(
        self,
        vault_address: str,
        consensus_endpoints: str,
        execution_endpoints: str,
        data_dir: Path,
        runner: CliRunner,
    ):
        args = [
            '--vault',
            vault_address,
            '--consensus-endpoints',
            consensus_endpoints,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
            '--data-dir',
            str(data_dir),
            '--no-confirm',
        ]
        consensus_validators = [
            create_consensus_validator(index=1, activation_epoch=DEFAULT_ACTIVATION_EPOCH - 500)
        ]
        public_keys = [val.public_key for val in consensus_validators]
        with (
            mock.patch(
                'src.commands.exit_validators.VaultContract.get_registered_validators_public_keys',
                return_value=public_keys,
            ),
            mock.patch(
                'src.commands.exit_validators.fetch_consensus_validators',
                return_value=consensus_validators,
            ),
            mock.patch(
                'src.commands.exit_validators.submit_withdraw_validators',
                return_value='0x12345',  # tx hash
            ) as submit_withdraw_validators,
        ):
            result = runner.invoke(exit_validators, args)
            submit_withdraw_validators.assert_called_once_with(
                withdrawals={key: 0 for key in public_keys},
                tx_fee=WITHDRAWAL_REQUEST_FEE,
                validators_manager_signature='0x',
            )
        assert result.exit_code == 0
        assert 'Exits for validators with index(es) 1 are successfully initiated\n' in result.output

    @pytest.mark.usefixtures('fake_settings')
    async def test_with_indexes(
        self,
        vault_address: str,
        consensus_endpoints: str,
        execution_endpoints: str,
        data_dir: Path,
        runner: CliRunner,
    ):
        args = [
            '--vault',
            vault_address,
            '--consensus-endpoints',
            consensus_endpoints,
            '--execution-endpoints',
            execution_endpoints,
            '--verbose',
            '--data-dir',
            str(data_dir),
            '--no-confirm',
            '--indexes',
            '1',
        ]
        consensus_validators = [
            create_consensus_validator(index=1, activation_epoch=DEFAULT_ACTIVATION_EPOCH - 500)
        ]
        public_keys = [val.public_key for val in consensus_validators]

        with (
            mock.patch(
                'src.commands.exit_validators.VaultContract.get_registered_validators_public_keys',
                return_value=public_keys,
            ),
            mock.patch(
                'src.commands.exit_validators.fetch_consensus_validators',
                return_value=consensus_validators,
            ),
            mock.patch(
                'src.commands.exit_validators.submit_withdraw_validators',
                return_value='0x12345',  # tx hash
            ) as submit_withdraw_validators,
        ):
            result = runner.invoke(exit_validators, args)
            submit_withdraw_validators.assert_called_once_with(
                withdrawals={key: 0 for key in public_keys},
                tx_fee=WITHDRAWAL_REQUEST_FEE,
                validators_manager_signature='0x',
            )
        assert result.exit_code == 0
        assert 'Exits for validators with index(es) 1 are successfully initiated\n' in result.output

    @pytest.mark.usefixtures('fake_settings')
    async def test_non_active_indexes(
        self,
        vault_address: str,
        consensus_endpoints: str,
        execution_endpoints: str,
        data_dir: Path,
        runner: CliRunner,
    ):
        args = [
            '--vault',
            vault_address,
            '--consensus-endpoints',
            consensus_endpoints,
            '--execution-endpoints',
            execution_endpoints,
            '--data-dir',
            str(data_dir),
            '--no-confirm',
            '--indexes',
            '1',
        ]
        consensus_validators = [
            create_consensus_validator(
                index=1,
                activation_epoch=DEFAULT_ACTIVATION_EPOCH - 500,
                status=ValidatorStatus.ACTIVE_EXITING,
            )
        ]
        with (
            mock.patch(
                'src.commands.exit_validators.VaultContract.get_registered_validators_public_keys',
                return_value=[validator.public_key for validator in consensus_validators],
            ),
            mock.patch(
                'src.commands.exit_validators.fetch_consensus_validators',
                return_value=consensus_validators,
            ),
            mock.patch(
                'src.commands.exit_validators.submit_withdraw_validators',
                return_value=None,
            ) as submit_withdraw_validators,
        ):
            result = runner.invoke(exit_validators, args)
            submit_withdraw_validators.assert_not_called()
        assert result.exit_code == 1
