import json
import os.path
from functools import cached_property

from eth_account import Account
from eth_account.account import LocalAccount

from src.config.settings import settings


class HotWallet:
    @cached_property
    def account(self) -> LocalAccount:
        HOT_WALLET_PRIVATE_KEY = settings.HOT_WALLET_PRIVATE_KEY
        HOT_WALLET_KEYSTORE_PATH = settings.HOT_WALLET_KEYSTORE_PATH
        HOT_WALLET_KEYSTORE_PASSWORD_PATH = settings.HOT_WALLET_KEYSTORE_PASSWORD_PATH

        if HOT_WALLET_PRIVATE_KEY:
            return Account().from_key(HOT_WALLET_PRIVATE_KEY)

        if HOT_WALLET_KEYSTORE_PATH and HOT_WALLET_KEYSTORE_PASSWORD_PATH:
            return self.load_password_protected_account(
                HOT_WALLET_KEYSTORE_PATH, HOT_WALLET_KEYSTORE_PASSWORD_PATH
            )

        raise ValueError(
            'Provide HOT_WALLET_PRIVATE_KEY setting or combination of '
            'HOT_WALLET_KEYSTORE_PATH and HOT_WALLET_KEYSTORE_PASSWORD_PATH settings'
        )

    def load_password_protected_account(self, keystore_path, password_path) -> LocalAccount:
        if not os.path.isfile(keystore_path):
            raise ValueError(f"Can't open key file. Path: {keystore_path}")
        if not os.path.isfile(password_path):
            raise ValueError(f"Can't open password file. Path: {password_path}")

        with open(keystore_path, 'r', encoding='utf-8') as f:
            keyfile_json = json.load(f)
        with open(password_path, 'r', encoding='utf-8') as f:
            password = f.read().strip()
        key = Account.decrypt(keyfile_json, password)
        return Account().from_key(key)

    def __getattr__(self, item):
        return getattr(self.account, item)


hot_wallet = HotWallet()
