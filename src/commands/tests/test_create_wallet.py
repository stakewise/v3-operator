import json
import unittest

from click.testing import CliRunner
from eth_account import Account
from staking_deposit.key_handling.key_derivation.mnemonic import get_mnemonic
from sw_utils.tests.factories import faker

from src.commands.create_wallet import create_wallet
from src.common.language import WORD_LISTS_PATH
from src.config.settings import DATA_DIR


class TestCreateWallet(unittest.TestCase):
    def test_basic(self):
        vault = faker.eth_address()
        vault_dir = f'{DATA_DIR}/{vault.lower()}'
        runner = CliRunner()
        Account.enable_unaudited_hdwallet_features()
        mnemonic = get_mnemonic(language='english', words_path=WORD_LISTS_PATH)
        account = Account().from_mnemonic(mnemonic=mnemonic)
        args = ['--mnemonic', f'"{mnemonic}"', '--vault', vault]
        with runner.isolated_filesystem():
            result = runner.invoke(create_wallet, args)
            assert result.exit_code == 0
            filename = 'wallet.json'
            output = 'Done. The wallet and password saved to'
            assert output.strip() in result.output.strip()
            with open(f'{vault_dir}/wallet/{filename}', encoding='utf-8') as f:
                data = json.load(f)
                assert data.get('address') == account.address.lower()[2:]
            with open(f'{vault_dir}/wallet/password.txt', encoding='utf-8') as f:
                assert len(f.readline()) == 20
