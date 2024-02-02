from pathlib import Path
from typing import Generator
from unittest import mock

import pytest
from click.testing import CliRunner
from eth_typing import HexAddress
from sw_utils.typings import ConsensusFork, ProtocolConfig

from src.commands.validators_exit import validators_exit
from src.config.settings import settings
from src.validators.keystores.local import LocalKeystore
from src.validators.keystores.remote import RemoteSignerKeystore


@pytest.fixture
def _patch_get_protocol_config(mocked_protocol_config: ProtocolConfig) -> Generator:
    with mock.patch(
        'src.commands.remote_signer_setup.get_protocol_config', return_value=mocked_protocol_config
    ):
        yield


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
def _patch_submit_voluntary_exit() -> Generator:
    with mock.patch(
        'sw_utils.consensus.ExtendedAsyncBeacon.submit_voluntary_exit',
        return_value=None,
    ):
        yield


@pytest.mark.usefixtures(
    '_patch_get_protocol_config', '_patch_get_consensus_fork', '_patch_submit_voluntary_exit'
)
@pytest.mark.usefixtures('_init_vault', '_create_keys')
class TestValidatorsExit:
    @pytest.mark.usefixtures('fake_settings')
    def test_local_keystores(
        self,
        vault_address: HexAddress,
        consensus_endpoints: str,
        data_dir: Path,
        vault_dir: Path,
        keystores_dir: Path,
        runner: CliRunner,
    ):
        # Get pubkey(s) to exit
        keystore_files = LocalKeystore.list_keystore_files()
        pubkeys = []
        for keystore_file in keystore_files:
            pubkey, _ = LocalKeystore._process_keystore_file(keystore_file, keystores_dir)
            pubkeys.append(pubkey)

        args = [
            '--vault',
            str(vault_address),
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
            result = runner.invoke(validators_exit, args, input='y')
        assert result.exit_code == 0
        assert 'Validators 0, 1, 2 (3 of 3) exits successfully initiated\n' in result.output

    @pytest.mark.usefixtures('_remote_signer_setup')
    def test_remote_signer(
        self,
        vault_address: HexAddress,
        consensus_endpoints: str,
        data_dir: Path,
        vault_dir: Path,
        keystores_dir: Path,
        runner: CliRunner,
        remote_signer_url: str,
    ):
        # Get pubkey(s) to exit
        config = RemoteSignerKeystore.load_from_file(settings.remote_signer_config_file)
        pubkeys = list(config.pubkeys_to_shares.keys())

        args = [
            '--vault',
            str(vault_address),
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
            result = runner.invoke(validators_exit, args, input='y')
        assert result.exit_code == 0

        for expected_line in ('Validators 0, 1, 2 (3 of 3) exits successfully initiated',):
            assert expected_line in result.output
