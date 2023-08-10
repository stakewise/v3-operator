from pathlib import Path
from typing import AsyncGenerator, Generator
from unittest import mock

import pytest
from click.testing import CliRunner
from eth_typing import HexAddress
from sw_utils.typings import ConsensusFork

from src.commands.validators_exit import validators_exit
from src.common.typings import Oracles
from src.config.settings import settings
from src.validators.signing.remote import RemoteSignerConfiguration
from src.validators.utils import _process_keystore_file, list_keystore_files


@pytest.fixture
async def _patch_get_oracles(mocked_oracles: Oracles) -> AsyncGenerator:
    with mock.patch('src.commands.generate_key_shares.get_oracles', return_value=mocked_oracles):
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
    '_patch_get_oracles', '_patch_get_consensus_fork', '_patch_submit_voluntary_exit'
)
@pytest.mark.usefixtures('_init_vault', '_create_keys')
class TestValidatorsExit:
    @pytest.mark.usefixtures('fake_settings')
    def test_local_keystores(
        self,
        vault_address: HexAddress,
        consensus_endpoints: str,
        data_dir: HexAddress,
        vault_dir: Path,
        keystores_dir: Path,
        runner: CliRunner,
    ):
        # Get pubkey(s) to exit
        keystore_files = list_keystore_files()
        pubkeys = []
        for keystore_file in keystore_files:
            pubkey, _ = _process_keystore_file(keystore_file, keystores_dir)
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

        assert 'Validators 0, 1, 2, 3, 4 exits successfully initiated\n' in result.output

    @pytest.mark.usefixtures('_mocked_remote_signer')
    def test_remote_signer(
        self,
        vault_address: HexAddress,
        consensus_endpoints: str,
        data_dir: HexAddress,
        vault_dir: Path,
        keystores_dir: Path,
        runner: CliRunner,
        remote_signer_url: str,
    ):
        # Get pubkey(s) to exit
        config = RemoteSignerConfiguration.from_file(settings.remote_signer_config_file)
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

        for expected_line in (
            f'Using remote signer at {remote_signer_url}',
            'Validators 0, 1, 2, 3, 4 exits successfully initiated',
        ):
            assert expected_line in result.output
