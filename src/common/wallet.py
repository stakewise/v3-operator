import json
import os.path
from functools import cached_property
from pathlib import Path

from eth_account import Account
from eth_account.account import LocalAccount

from src.config.settings import settings


class HotWallet:
    @property
    def private_key(self) -> str | None:
        return settings.HOT_WALLET_PRIVATE_KEY

    @property
    def keystore_path(self) -> Path:
        keystore_path = settings.HOT_WALLET_KEYSTORE_PATH
        vault_dir = settings.VAULT_DIR

        return keystore_path or vault_dir / 'wallet' / 'wallet.json'

    @property
    def keystore_password_path(self) -> Path:
        keystore_password_path = settings.HOT_WALLET_KEYSTORE_PASSWORD_PATH
        vault_dir = settings.VAULT_DIR

        return keystore_password_path or vault_dir / 'wallet' / 'password.txt'

    def can_load(self) -> bool:
        try:
            self.account
        except ValueError:
            return False
        return True

    @cached_property
    def account(self) -> LocalAccount:
        if self.private_key:
            return Account().from_key(self.private_key)

        if self.keystore_path and self.keystore_password_path:
            return self.load_password_protected_account()

        raise ValueError(
            'Provide HOT_WALLET_PRIVATE_KEY setting or combination of '
            'HOT_WALLET_KEYSTORE_PATH and HOT_WALLET_KEYSTORE_PASSWORD_PATH settings'
        )

    def load_password_protected_account(self) -> LocalAccount:
        if not os.path.isfile(self.keystore_path):
            raise ValueError(f"Can't open key file. Path: {self.keystore_path}")
        if not os.path.isfile(self.password_path):
            raise ValueError(f"Can't open password file. Path: {self.password_path}")

        with open(self.keystore_path, 'r', encoding='utf-8') as f:
            keyfile_json = json.load(f)
        with open(self.password_path, 'r', encoding='utf-8') as f:
            password = f.read().strip()
        key = Account.decrypt(keyfile_json, password)
        return Account().from_key(key)

    def __getattr__(self, item):
        return getattr(self.account, item)


hot_wallet = HotWallet()
