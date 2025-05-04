import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from eth_account import Account

from src.commands.create_wallet import create_wallet


class TestCreateWallet:
    @pytest.mark.usefixtures('_init_config')
    def test_basic(
        self,
        test_mnemonic: str,
        data_dir: Path,
        config_dir: Path,
        runner: CliRunner,
    ):
        Account.enable_unaudited_hdwallet_features()
        account = Account().from_mnemonic(mnemonic=test_mnemonic)
        result = runner.invoke(
            create_wallet,
            [
                '--mnemonic',
                f'"{test_mnemonic}"',
                '--data-dir',
                str(data_dir),
            ],
        )
        assert result.exit_code == 0
        filename = 'wallet.json'
        output = 'Done. The wallet and password saved to'
        assert output.strip() in result.output.strip()
        with open(f'{config_dir}/wallet/{filename}', encoding='utf-8') as f:
            data = json.load(f)
            assert data.get('address').lower() == account.address.lower()[2:]
        with open(f'{config_dir}/wallet/password.txt', encoding='utf-8') as f:
            assert len(f.readline()) == 20
