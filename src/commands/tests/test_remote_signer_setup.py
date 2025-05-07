from pathlib import Path

import aiohttp
import pytest
from click.testing import CliRunner
from eth_typing import HexAddress

from src.commands.create_keys import create_keys
from src.commands.remote_signer_setup import remote_signer_setup
from src.config.settings import settings


class TestOperatorRemoteSignerSetup:
    @pytest.mark.usefixtures(
        '_init_config',
        '_create_keys',
        'mocked_remote_signer',
    )
    async def test_basic(
        self,
        vault_address: HexAddress,
        data_dir: Path,
        config_dir: Path,
        keystores_dir: Path,
        remote_signer_url: str,
        runner: CliRunner,
    ):
        key_count = 3

        args = [
            '--remote-signer-url',
            remote_signer_url,
            '--data-dir',
            str(data_dir),
        ]

        result = runner.invoke(remote_signer_setup, args, input='y')
        assert result.exit_code == 0
        for expected_output_message in [
            f'Successfully imported {key_count} keys into remote signer.',
            'Removed keystores from local filesystem.',
            'Done.'
            f' Successfully configured operator to use remote signer for {key_count} public key(s)!',
        ]:
            assert expected_output_message in result.output

        assert keystores_dir.exists() is False

        async with aiohttp.ClientSession() as session:
            resp = await session.get(f'{settings.remote_signer_url}/eth/v1/keystores')
            data = (await resp.json())['data']
            pubkeys_remote_signer = {pubkey_dict.get('validating_pubkey') for pubkey_dict in data}
            assert len(pubkeys_remote_signer) == key_count

    @pytest.mark.usefixtures('_init_config', 'mocked_remote_signer')
    def test_add_more_keys_later(
        self,
        vault_address: HexAddress,
        test_mnemonic: str,
        data_dir: Path,
        config_dir: Path,
        remote_signer_url: str,
        keystores_dir: Path,
        runner: CliRunner,
    ):
        key_count_first_batch = 3
        key_count_second_batch = 2

        # Run create-keys and operator-remote-signer-setup twice
        for key_count in (key_count_first_batch, key_count_second_batch):
            args = [
                '--mnemonic',
                test_mnemonic,
                '--count',
                str(key_count),
                '--data-dir',
                str(data_dir),
            ]
            result = runner.invoke(create_keys, args)
            assert result.exit_code == 0
            assert f'Done. Generated {key_count} keys' in result.output

            args = [
                '--remote-signer-url',
                remote_signer_url,
                '--data-dir',
                str(data_dir),
            ]

            result = runner.invoke(remote_signer_setup, args, input='y')
            assert result.exit_code == 0
            assert (
                f'Done. Successfully configured operator to use remote signer for {key_count} public key(s)'
                in result.output
            )
