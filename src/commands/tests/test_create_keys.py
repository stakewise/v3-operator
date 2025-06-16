import glob
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from src.commands.create_keys import create_keys
from src.config.settings import PUBLIC_KEYS_FILENAME


@pytest.mark.usefixtures('_init_config')
class TestCreateKeys:
    def test_basic_0x01(
        self,
        test_mnemonic: str,
        data_dir: Path,
        config_dir: Path,
        runner: CliRunner,
    ):
        count = 5

        args = [
            '--mnemonic',
            test_mnemonic,
            '--count',
            str(count),
            '--data-dir',
            str(data_dir),
            '--validator-type',
            '0x01',
            '--pool-size',
            '1',
        ]
        result = runner.invoke(create_keys, args)
        assert result.exit_code == 0

        output = (
            'Creating validator keys:\t\t\n'
            'Exporting validator keystores\t\t\n'
            f'Done. Generated 5 keys for StakeWise operator.\n'
            f'Keystores saved to {config_dir}/keystores file\n'
            f'Validator public keys saved to {config_dir}/{PUBLIC_KEYS_FILENAME} file'
        )
        assert output.strip() == result.output.strip()
        with open(f'{config_dir}/{PUBLIC_KEYS_FILENAME}', encoding='utf-8') as f:
            public_keys = [line.rstrip() for line in f]
            assert count == len(public_keys)
        with open(f'{config_dir}/keystores/password.txt', encoding='utf-8') as f:
            assert len(f.readline()) == 20

        assert len(os.listdir(f'{config_dir}/keystores')) == count + 1
        assert len(os.listdir(f'{config_dir}/keystores')) == count + 1

    def test_basic_0x02(
        self,
        test_mnemonic: str,
        data_dir: Path,
        config_dir: Path,
        runner: CliRunner,
    ):
        count = 5

        args = [
            '--mnemonic',
            test_mnemonic,
            '--count',
            str(count),
            '--data-dir',
            str(data_dir),
            '--validator-type',
            '0x02',
            '--pool-size',
            '1',
        ]
        result = runner.invoke(create_keys, args)
        assert result.exit_code == 0

        output = (
            'Creating validator keys:\t\t\n'
            'Exporting validator keystores\t\t\n'
            f'Done. Generated 5 keys for StakeWise operator.\n'
            f'Keystores saved to {config_dir}/keystores file\n'
            f'Validator public keys saved to {config_dir}/{PUBLIC_KEYS_FILENAME} file'
        )
        assert output.strip() == result.output.strip()
        with open(f'{config_dir}/{PUBLIC_KEYS_FILENAME}', encoding='utf-8') as f:
            public_keys = [line.rstrip() for line in f]
            assert count == len(public_keys)
        with open(f'{config_dir}/keystores/password.txt', encoding='utf-8') as f:
            assert len(f.readline()) == 20

        assert len(os.listdir(f'{config_dir}/keystores')) == count + 1

    def test_per_keystore_password(
        self,
        test_mnemonic: str,
        data_dir: Path,
        config_dir: Path,
        keystores_dir: Path,
        runner: CliRunner,
    ):
        count = 5

        args = [
            '--mnemonic',
            f'"{test_mnemonic}"',
            '--count',
            str(count),
            '--data-dir',
            str(data_dir),
            '--pool-size',
            '1',
            '--per-keystore-password',
        ]
        result = runner.invoke(create_keys, args)
        assert result.exit_code == 0

        output = (
            'Creating validator keys:\t\t\n'
            'Exporting validator keystores\t\t\n'
            f'Done. Generated 5 keys for StakeWise operator.\n'
            f'Keystores saved to {config_dir}/keystores file\n'
            f'Validator public keys saved to {config_dir}/{PUBLIC_KEYS_FILENAME} file'
        )
        assert output.strip() == result.output.strip()
        with open(f'{config_dir}/{PUBLIC_KEYS_FILENAME}', encoding='utf-8') as f:
            public_keys = [line.rstrip() for line in f]
            assert count == len(public_keys)
        password_files = glob.glob(os.path.join(keystores_dir / '*.txt'))
        assert len(password_files) == count
        for password_file in password_files:
            with open(password_file, 'r', encoding='utf-8') as f:
                assert len(f.readline()) == 20
        assert len(os.listdir(f'{config_dir}/keystores')) == count * 2
