from pathlib import Path
from typing import Generator
from unittest import mock

import pytest
from click.testing import CliRunner
from sw_utils.typings import ConsensusFork

from src.commands.exit_validators import exit_validators
from src.validators.keystores.local import LocalKeystore
from src.validators.keystores.remote import RemoteSignerKeystore


@pytest.fixture
def _patch_get_consensus_fork() -> Generator:
    with mock.patch(
        'sw_utils.consensus.ExtendedAsyncBeacon.get_consensus_fork',
        return_value=ConsensusFork(
            version=bytes.fromhex('00000000'),
            epoch=1,
        ),
    ):
        yield


@pytest.fixture
def _patch_submit_withdraw_validators() -> Generator:
    with mock.patch(
        'src.commands.exit_validators.submit_withdraw_validators',
        return_value=None,
    ):
        yield


@pytest.mark.usefixtures('_patch_get_consensus_fork', '_patch_submit_withdraw_validators')
@pytest.mark.usefixtures('_init_config', '_create_keys')
class TestValidatorsExit:
    @pytest.mark.usefixtures('fake_settings')
    def test_local_keystores(
        self,
        consensus_endpoints: str,
        data_dir: Path,
        config_dir: Path,
        keystores_dir: Path,
        runner: CliRunner,
    ):
        # Get pubkey(s) to exit
        keystore_files = LocalKeystore.list_keystore_files()
        pubkeys = []
        for keystore_file in keystore_files:
            pubkey, _, _ = LocalKeystore._process_keystore_file(keystore_file, keystores_dir)
            pubkeys.append(pubkey)

        args = [
            '--data-dir',
            str(data_dir),
            '--consensus-endpoints',
            consensus_endpoints,
        ]

        with (
            mock.patch(
                'sw_utils.consensus.ExtendedAsyncBeacon.get_validators_by_ids',
                return_value={
                    'data': [
                        {
                            'status': 'active',
                            'index': idx,
                            'validator': {
                                'pubkey': pubkey,
                            },
                        }
                        for idx, pubkey in enumerate(pubkeys)
                    ]
                },
            ),
        ):
            result = runner.invoke(exit_validators, args, input='y')
        assert result.exit_code == 0
        assert 'Validators 0, 1, 2 (3 of 3) exits successfully initiated\n' in result.output

    @pytest.mark.usefixtures('_setup_remote_signer')
    async def test_remote_signer(
        self,
        consensus_endpoints: str,
        data_dir: Path,
        config_dir: Path,
        keystores_dir: Path,
        runner: CliRunner,
        remote_signer_url: str,
    ):
        # Get pubkey(s) to exit
        keystore = await RemoteSignerKeystore.load()
        pubkeys = keystore.public_keys

        args = [
            '--data-dir',
            str(data_dir),
            '--consensus-endpoints',
            consensus_endpoints,
            '--remote-signer-url',
            remote_signer_url,
        ]

        with (
            mock.patch(
                'sw_utils.consensus.ExtendedAsyncBeacon.get_validators_by_ids',
                return_value={
                    'data': [
                        {
                            'status': 'active',
                            'index': idx,
                            'validator': {
                                'pubkey': pubkey,
                            },
                        }
                        for idx, pubkey in enumerate(pubkeys)
                    ]
                },
            ),
        ):
            result = runner.invoke(exit_validators, args, input='y')
        assert result.exit_code == 0

        for expected_line in ('Validators 0, 1, 2 (3 of 3) exits successfully initiated',):
            assert expected_line in result.output
