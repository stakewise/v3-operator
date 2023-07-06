import json
import unittest

from click.testing import CliRunner
from eth_account import Account
from sw_utils.tests.factories import faker

from src.commands.create_wallet import create_wallet
from src.commands.init import init
from src.config.settings import DATA_DIR


class TestCreateWallet(unittest.TestCase):
    def test_basic(self):
        vault = faker.eth_address()
        vault_dir = f'{DATA_DIR}/{vault.lower()}'
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
            Account.enable_unaudited_hdwallet_features()
            account = Account().from_mnemonic(mnemonic=mnemonic)
            result = runner.invoke(create_wallet, ['--mnemonic', f'"{mnemonic}"', '--vault', vault])
            assert result.exit_code == 0
            filename = 'wallet.json'
            output = 'Done. The wallet and password saved to'
            assert output.strip() in result.output.strip()
            with open(f'{vault_dir}/wallet/{filename}', encoding='utf-8') as f:
                data = json.load(f)
                assert data.get('address') == account.address.lower()[2:]
            with open(f'{vault_dir}/wallet/password.txt', encoding='utf-8') as f:
                assert len(f.readline()) == 20
