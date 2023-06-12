import json
import os
import unittest

from click.testing import CliRunner
from staking_deposit.key_handling.key_derivation.mnemonic import get_mnemonic

import src
from src.commands.create_keys import create_keys
from src.commands.init import init
from src.common.language import WORD_LISTS_PATH
from src.config.settings import CONFIG_DIR

from .factories import faker

mnemonic = get_mnemonic(language='english', words_path=WORD_LISTS_PATH)


class TestCreateKeys(unittest.TestCase):
    def test_basic(self):
        vault = faker.eth_address()
        count = 5
        runner = CliRunner()
        args = [
            '--mnemonic',
            f'"{mnemonic}"',
            '--count',
            count,
            '--vault',
            vault
        ]
        args_init = [
            '--language',
            'english',
            '--no-verify',
            '--vault',
            vault,
            '--network',
            'goerli'
        ]
        with runner.isolated_filesystem():
            runner.invoke(init, args_init)
            result = runner.invoke(create_keys, args)
            assert result.exit_code == 0

            vault_dir = f'{CONFIG_DIR}/{vault}'

            output = (
                'Creating validator keys:\t\t\n'
                'Generating deposit data JSON\t\t\n'
                'Exporting validator keystores\t\t\n'
                f'Successfully updated configuration for vault {vault}\n'
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
                assert data[0].get('deposit_cli_version') == src.__version__
            with open(f'{vault_dir}/keystores/password.txt', encoding='utf-8') as f:
                assert len(f.readline()) == 20

            assert len(os.listdir(f'{vault_dir}/keystores')) == count + 1
