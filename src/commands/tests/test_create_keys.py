import glob
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner
from eth_typing import HexAddress
from staking_deposit.settings import DEPOSIT_CLI_VERSION

from src.commands.create_keys import create_keys


@pytest.mark.usefixtures('_init_vault')
class TestCreateKeys:
    def test_basic(
        self,
        test_mnemonic: str,
        data_dir: Path,
        vault_address: HexAddress,
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
            '--pool-size',
            '1',
        ]
        result = runner.invoke(create_keys, args)
        assert result.exit_code == 0

        output = (
            'Creating validator keys:\t\t\n'
            'Generating deposit data JSON\t\t\n'
            'Exporting validator keystores\t\t\n'
            f'Done. Generated 5 keys for {vault_address} vault.\n'
            f'Keystores saved to {vault_dir}/keystores file\n'
            f'Deposit data saved to {vault_dir}/deposit_data.json file'
        )
        assert output.strip() == result.output.strip()
        with open(f'{vault_dir}/deposit_data.json', encoding='utf-8') as f:
            data = json.load(f)
            assert count == len(data)
            assert data[0].get('network_name') == 'hoodi'
            assert data[0].get('fork_version') == '10000910'
            assert data[0].get('deposit_cli_version') == DEPOSIT_CLI_VERSION
        with open(f'{vault_dir}/keystores/password.txt', encoding='utf-8') as f:
            assert len(f.readline()) == 20

        assert len(os.listdir(f'{vault_dir}/keystores')) == count + 1

    def test_per_keystore_password(
        self,
        test_mnemonic: str,
        data_dir: Path,
        vault_dir: Path,
        keystores_dir: Path,
        vault_address: HexAddress,
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
            '--pool-size',
            '1',
            '--per-keystore-password',
        ]
        result = runner.invoke(create_keys, args)
        assert result.exit_code == 0

        output = (
            'Creating validator keys:\t\t\n'
            'Generating deposit data JSON\t\t\n'
            'Exporting validator keystores\t\t\n'
            f'Done. Generated 5 keys for {vault_address} vault.\n'
            f'Keystores saved to {vault_dir}/keystores file\n'
            f'Deposit data saved to {vault_dir}/deposit_data.json file'
        )
        assert output.strip() == result.output.strip()
        with open(f'{vault_dir}/deposit_data.json', encoding='utf-8') as f:
            data = json.load(f)
            assert count == len(data)
            assert data[0].get('network_name') == 'hoodi'
            assert data[0].get('fork_version') == '10000910'
            assert data[0].get('deposit_cli_version') == DEPOSIT_CLI_VERSION
        password_files = glob.glob(os.path.join(keystores_dir / '*.txt'))
        assert len(password_files) == count
        for password_file in password_files:
            with open(password_file, 'r', encoding='utf-8') as f:
                assert len(f.readline()) == 20
        assert len(os.listdir(f'{vault_dir}/keystores')) == count * 2
