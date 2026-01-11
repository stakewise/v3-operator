import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from eth_typing import ChecksumAddress

from src.commands.create_keys import create_keys


@pytest.mark.usefixtures('_init_config')
class TestCreateKeys:
    def test_basic(
        self,
        test_mnemonic: str,
        data_dir: Path,
        vault_address: ChecksumAddress,
        vault_dir: Path,
        runner: CliRunner,
    ):
        count = 5

        args = [
            '--mnemonic',
            test_mnemonic,
            '--count',
            str(count),
            '--vault',
            str(vault_address),
            '--data-dir',
            str(data_dir),
            '--concurrency',
            '1',
        ]
        result = runner.invoke(create_keys, args)
        assert result.exit_code == 0

        output = (
            'Creating validator keys:\t\t\n'
            'Exporting validator keystores\t\t\n'
            f'Done. Generated 5 keys for StakeWise operator.\n'
            f'Keystores saved to {vault_dir}/keystores file\n'
        )
        assert output.strip() == result.output.strip()
        with open(f'{vault_dir}/keystores/password.txt', encoding='utf-8') as f:
            assert len(f.readline()) == 20

        assert len(os.listdir(f'{vault_dir}/keystores')) == count + 1

    def test_per_keystore_password(
        self,
        test_mnemonic: str,
        data_dir: Path,
        vault_address: ChecksumAddress,
        vault_dir: Path,
        keystores_dir: Path,
        runner: CliRunner,
    ):
        count = 5

        args = [
            '--mnemonic',
            f'"{test_mnemonic}"',
            '--count',
            str(count),
            '--vault',
            str(vault_address),
            '--data-dir',
            str(data_dir),
            '--concurrency',
            '1',
            '--per-keystore-password',
        ]
        result = runner.invoke(create_keys, args)
        assert result.exit_code == 0

        output = (
            'Creating validator keys:\t\t\n'
            'Exporting validator keystores\t\t\n'
            f'Done. Generated 5 keys for StakeWise operator.\n'
            f'Keystores saved to {vault_dir}/keystores file\n'
        )
        assert output.strip() == result.output.strip()
        password_files = list(keystores_dir.glob('*.txt'))
        assert len(password_files) == count
        for password_file in password_files:
            with open(password_file, 'r', encoding='utf-8') as f:
                assert len(f.readline()) == 20
        assert len(os.listdir(f'{vault_dir}/keystores')) == count * 2
