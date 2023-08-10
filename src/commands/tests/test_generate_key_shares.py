import os
from pathlib import Path
from typing import AsyncGenerator
from unittest import mock

import pytest
from click.testing import CliRunner
from eth_typing import HexAddress

from src.commands.create_keys import create_keys
from src.commands.generate_key_shares import generate_key_shares
from src.common.typings import Oracles
from src.config.settings import settings
from src.validators.signing.remote import RemoteSignerConfiguration
from src.validators.signing.tests.oracle_functions import OracleCommittee


@pytest.fixture
async def _patch_get_oracles(mocked_oracles: Oracles) -> AsyncGenerator:
    with mock.patch('src.commands.generate_key_shares.get_oracles', return_value=mocked_oracles):
        yield


@pytest.mark.usefixtures('_patch_get_oracles')
class TestGenerateKeyShares:
    def test_invalid_input(
        self,
        vault_address: HexAddress,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        result = runner.invoke(
            generate_key_shares,
            [
                '--vault',
                vault_address,
                '--execution-endpoints',
                execution_endpoints,
            ],
        )
        assert result.exit_code == 2
        assert "Error: Missing option '--output-dir'" in result.output

    @pytest.mark.usefixtures('_init_vault', '_create_keys')
    def test_basic(
        self,
        vault_address: HexAddress,
        execution_endpoints: str,
        data_dir: HexAddress,
        vault_dir: Path,
        keystores_dir: Path,
        remote_signer_keystores_dir: Path,
        runner: CliRunner,
        _mocked_oracle_committee: OracleCommittee,
    ):
        key_count = 5

        oracle_count = len(_mocked_oracle_committee.oracle_pubkeys)

        args = [
            '--vault',
            str(vault_address),
            '--data-dir',
            str(data_dir),
            '--execution-endpoints',
            execution_endpoints,
            '--output-dir',
            str(remote_signer_keystores_dir),
        ]

        result = runner.invoke(generate_key_shares, args)
        assert result.exit_code == 0
        for eo in [
            'Exporting validator keystores',
            'Successfully generated 55 key shares for 5 private key(s)!',
            'Removed local keystores.',
            'Successfully configured operator to use remote signer for 5 public key(s)!',
        ]:
            assert eo in result.output

        assert len(os.listdir(remote_signer_keystores_dir)) == key_count * oracle_count

        assert settings.remote_signer_config_file.is_file()

        config = RemoteSignerConfiguration.from_file(settings.remote_signer_config_file)

        assert len(config.pubkeys_to_shares) == key_count

        for _, shares in config.pubkeys_to_shares.items():
            assert len(shares) == oracle_count

    @pytest.mark.usefixtures('_init_vault')
    def test_add_more_keys_later(
        self,
        vault_address: HexAddress,
        test_mnemonic: str,
        execution_endpoints: str,
        data_dir: HexAddress,
        vault_dir: Path,
        keystores_dir: Path,
        remote_signer_keystores_dir: Path,
        runner: CliRunner,
        _mocked_oracle_committee: OracleCommittee,
    ):
        key_count_first_batch = 3
        key_count_second_batch = 5
        key_count_total = key_count_first_batch + key_count_second_batch

        # Run create-keys and generate-key-shares twice
        for key_count in (key_count_first_batch, key_count_second_batch):
            args = [
                '--mnemonic',
                test_mnemonic,
                '--count',
                str(key_count),
                '--vault',
                str(vault_address),
                '--data-dir',
                str(data_dir),
            ]
            result = runner.invoke(create_keys, args)
            assert result.exit_code == 0
            assert f'Done. Generated {key_count} keys' in result.output

            args = [
                '--vault',
                str(vault_address),
                '--data-dir',
                str(data_dir),
                '--execution-endpoints',
                execution_endpoints,
                '--output-dir',
                str(remote_signer_keystores_dir),
            ]

            result = runner.invoke(generate_key_shares, args)
            assert result.exit_code == 0
            assert (
                f'Done. Successfully configured operator to use remote signer for {key_count} public key(s)'
                in result.output
            )

        # The remote signer configuration should contain public keys and their
        # corresponding shares from both key batches
        config = RemoteSignerConfiguration.from_file(settings.remote_signer_config_file)
        assert len(config.pubkeys_to_shares) == key_count_total
