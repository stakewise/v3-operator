import glob
import json
import os
import unittest

from click.testing import CliRunner
from staking_deposit.settings import DEPOSIT_CLI_VERSION
from sw_utils.tests.factories import faker

from src.commands.create_keys import create_keys
from src.commands.init import init
from src.config.settings import DATA_DIR


class TestCreateKeys(unittest.TestCase):
    def test_basic(self):
        vault = faker.eth_address()
        count = 5
        runner = CliRunner()

        with runner.isolated_filesystem():
            args_init = [
                '--language',
                'english',
                '--no-verify',
                '--vault',
                vault,
                '--network',
                'goerli',
            ]
            init_result = runner.invoke(init, args_init)
            mnemonic = init_result.output.strip()
            args = ['--mnemonic', f'"{mnemonic}"', '--count', count, '--vault', vault]
            result = runner.invoke(create_keys, args)
            assert result.exit_code == 0

            vault_dir = f'{DATA_DIR}/{vault}'

            output = (
                'Creating validator keys:\t\t\n'
                'Generating deposit data JSON\t\t\n'
                'Exporting validator keystores\t\t\n'
                f'Done. Generated 5 keys for {vault} vault.\n'
                f'Keystores saved to {vault_dir}/keystores file\n'
                f'Deposit data saved to {vault_dir}/deposit_data.json file'
            )
            assert output.strip() == result.output.strip()
            with open(f'{vault_dir}/deposit_data.json', encoding='utf-8') as f:
                data = json.load(f)
                assert count == len(data)
                assert data[0].get('network_name') == 'goerli'
                assert data[0].get('fork_version') == '00001020'
                assert data[0].get('deposit_cli_version') == DEPOSIT_CLI_VERSION
            with open(f'{vault_dir}/keystores/password.txt', encoding='utf-8') as f:
                assert len(f.readline()) == 20

            assert len(os.listdir(f'{vault_dir}/keystores')) == count + 1

    def test_per_keystore_password(self):
        vault = faker.eth_address()
        count = 5
        runner = CliRunner()

        with runner.isolated_filesystem():
            args_init = [
                '--language',
                'english',
                '--no-verify',
                '--vault',
                vault,
                '--network',
                'goerli',
            ]
            init_result = runner.invoke(init, args_init)
            mnemonic = init_result.output.strip()
            args = [
                '--mnemonic',
                f'"{mnemonic}"',
                '--count',
                count,
                '--vault',
                vault,
                '--per-keystore-password',
            ]
            result = runner.invoke(create_keys, args)
            assert result.exit_code == 0

            vault_dir = f'{DATA_DIR}/{vault}'

            output = (
                'Creating validator keys:\t\t\n'
                'Generating deposit data JSON\t\t\n'
                'Exporting validator keystores\t\t\n'
                f'Done. Generated 5 keys for {vault} vault.\n'
                f'Keystores saved to {vault_dir}/keystores file\n'
                f'Deposit data saved to {vault_dir}/deposit_data.json file'
            )
            assert output.strip() == result.output.strip()
            with open(f'{vault_dir}/deposit_data.json', encoding='utf-8') as f:
                data = json.load(f)
                assert count == len(data)
                assert data[0].get('network_name') == 'goerli'
                assert data[0].get('fork_version') == '00001020'
                assert data[0].get('deposit_cli_version') == DEPOSIT_CLI_VERSION
            password_files = glob.glob(os.path.join(vault_dir, '/keystores/*.txt'))
            for password_file in password_files:
                with open(password_file, 'r', encoding='utf-8') as f:
                    assert len(f.readline()) == 20
            assert len(os.listdir(f'{vault_dir}/keystores')) == count * 2
