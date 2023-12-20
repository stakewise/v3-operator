import os
from pathlib import Path
from typing import Generator
from unittest import mock

import aiohttp
import pytest
from click.testing import CliRunner
from eth_typing import HexAddress

from src.commands.create_keys import create_keys
from src.commands.remote_signer_setup import remote_signer_setup
from src.common.typings import Oracles
from src.common.vault_config import VaultConfig
from src.config.networks import HOLESKY
from src.config.settings import settings
from src.validators.signing.remote import RemoteSignerConfiguration
from src.validators.signing.tests.oracle_functions import OracleCommittee


@pytest.fixture
def _patch_get_oracles(mocked_oracles: Oracles) -> Generator:
    with mock.patch('src.commands.remote_signer_setup.get_oracles', return_value=mocked_oracles):
        yield


@pytest.mark.usefixtures('_patch_get_oracles')
class TestOperatorRemoteSignerSetup:
    @pytest.mark.usefixtures('_init_vault')
    def test_invalid_input(
        self,
        vault_address: HexAddress,
        data_dir: Path,
        execution_endpoints: str,
        runner: CliRunner,
    ):
        result = runner.invoke(
            remote_signer_setup,
            [
                '--vault',
                vault_address,
                '--execution-endpoints',
                execution_endpoints,
            ],
        )
        assert result.exit_code == 2
        assert "Error: Missing option '--remote-signer-url'" in result.output

    @pytest.mark.usefixtures(
        '_init_vault', '_create_keys', 'mocked_remote_signer', 'mock_scrypt_keystore'
    )
    async def test_basic(
        self,
        vault_address: HexAddress,
        execution_endpoints: str,
        data_dir: Path,
        vault_dir: Path,
        keystores_dir: Path,
        remote_signer_url: str,
        runner: CliRunner,
        _mocked_oracle_committee: OracleCommittee,
    ):
        key_count = 3

        oracle_count = len(_mocked_oracle_committee.oracle_pubkeys)

        args = [
            '--vault',
            str(vault_address),
            '--remote-signer-url',
            remote_signer_url,
            '--data-dir',
            str(data_dir),
            '--execution-endpoints',
            execution_endpoints,
        ]

        result = runner.invoke(remote_signer_setup, args)
        assert result.exit_code == 0
        for expected_output_message in [
            f'Successfully generated {oracle_count * key_count} key shares for {key_count} private key(s)!',
            f'Successfully imported {oracle_count * key_count} key shares into remote signer.',
            'Removed keystores from local filesystem.',
            'Done.'
            f' Successfully configured operator to use remote signer for {key_count} public key(s)!',
        ]:
            assert expected_output_message in result.output

        assert len(os.listdir(keystores_dir)) == 0

        assert settings.remote_signer_config_file.is_file()

        config = RemoteSignerConfiguration.from_file(settings.remote_signer_config_file)

        assert len(config.pubkeys_to_shares) == key_count

        for _, shares in config.pubkeys_to_shares.items():
            assert len(shares) == oracle_count

        async with aiohttp.ClientSession() as session:
            resp = await session.get(f'{settings.remote_signer_url}/eth/v1/keystores')
            data = (await resp.json())['data']
            pubkeys_remote_signer = {pubkey_dict.get('validating_pubkey') for pubkey_dict in data}
            assert len(pubkeys_remote_signer) == key_count * oracle_count

    @pytest.mark.usefixtures('_init_vault', 'mocked_remote_signer', 'mock_scrypt_keystore')
    def test_add_more_keys_later(
        self,
        vault_address: HexAddress,
        test_mnemonic: str,
        execution_endpoints: str,
        data_dir: Path,
        vault_dir: Path,
        remote_signer_url: str,
        keystores_dir: Path,
        runner: CliRunner,
        _mocked_oracle_committee: OracleCommittee,
    ):
        key_count_first_batch = 3
        key_count_second_batch = 2
        key_count_total = key_count_first_batch + key_count_second_batch

        # Run create-keys and operator-remote-signer-setup twice
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
                '--remote-signer-url',
                remote_signer_url,
                '--data-dir',
                str(data_dir),
                '--execution-endpoints',
                execution_endpoints,
            ]

            result = runner.invoke(remote_signer_setup, args)
            assert result.exit_code == 0
            assert (
                f'Done. Successfully configured operator to use remote signer for {key_count} public key(s)'
                in result.output
            )

        # The remote signer configuration should contain public keys and their
        # corresponding shares from both key batches
        config = RemoteSignerConfiguration.from_file(settings.remote_signer_config_file)
        assert len(config.pubkeys_to_shares) == key_count_total

    @pytest.mark.parametrize(['remove_existing_keys'], [pytest.param(False), pytest.param(True)])
    @pytest.mark.usefixtures('_init_vault', '_remote_signer_setup', 'mock_scrypt_keystore')
    def test_oracle_set_change(
        self,
        vault_address: HexAddress,
        remove_existing_keys: bool,
        data_dir: Path,
        vault_dir: Path,
        remote_signer_url: str,
        keystores_dir: Path,
        execution_endpoints: str,
        test_mnemonic: str,
        runner: CliRunner,
        mocked_oracles: Oracles,
        _mocked_oracle_committee: OracleCommittee,
    ):
        """
        When the set of oracles changes, the keyshares in the remote signer need to be updated.
        This test simulates that process by:
        - using the _remote_signer_setup to import the first set of keyshares into the remote signer
        - adjusting the set of oracles
        - running the remote-signer-setup command again to import the new key shares
        """
        # Remote signer is initially set up with the default mocked oracle set.
        prev_oracle_count = len(_mocked_oracle_committee.oracle_pubkeys)

        # We remove 1 oracle and run the `remote-signer-setup` command again.
        mocked_oracles.public_keys.pop()
        assert len(mocked_oracles.public_keys) >= mocked_oracles.exit_signature_recover_threshold

        # We also need to reset the mnemonic_next_index value so the keys are generated from
        # the 0th index again.
        vault_config = VaultConfig(vault=vault_address, data_dir=data_dir)
        vault_config.load()
        key_count = vault_config.mnemonic_next_index
        vault_config.save(network=HOLESKY, mnemonic=test_mnemonic, mnemonic_next_index=0)

        prev_key_share_count = key_count * prev_oracle_count
        expected_new_key_share_count = key_count * (prev_oracle_count - 1)

        # Create the same amount of validator keys as before
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

        # Run the remote-signer-setup command - it should generate and import
        # a lower amount of key shares - there are fewer oracles now
        with mock.patch(
            'src.commands.remote_signer_setup.get_oracles', return_value=mocked_oracles
        ):
            args = [
                '--vault',
                str(vault_address),
                '--remote-signer-url',
                remote_signer_url,
                '--data-dir',
                str(data_dir),
                '--execution-endpoints',
                execution_endpoints,
            ]

            if remove_existing_keys:
                args.append('--remove-existing-keys')

            result = runner.invoke(remote_signer_setup, args)
            assert result.exit_code == 0

            for msg in (
                f'Successfully generated {expected_new_key_share_count} key shares for {key_count} private key(s)!',
                f'Done. Successfully configured operator to use remote signer for {key_count} public key(s)!',
            ):
                assert msg in result.output

            assert (
                f'Removed {prev_key_share_count} keys from remote signer' in result.output
            ) is remove_existing_keys
