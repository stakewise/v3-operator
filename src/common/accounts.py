import json
import os.path

from eth_account import Account
from eth_account.account import LocalAccount

from src.config.settings import (
    HOT_WALLET_KEYSTORE_PASSWORD_PATH,
    HOT_WALLET_KEYSTORE_PATH,
    HOT_WALLET_PRIVATE_KEY,
)


def get_operator_account() -> LocalAccount:
    if HOT_WALLET_PRIVATE_KEY:
        return Account().from_key(HOT_WALLET_PRIVATE_KEY)

    if HOT_WALLET_KEYSTORE_PATH and HOT_WALLET_KEYSTORE_PASSWORD_PATH:
        if not os.path.isfile(HOT_WALLET_KEYSTORE_PATH):
            raise ValueError(f"Can't open HOT_WALLET_KEYSTORE_PATH file. "
                             f' Path: {HOT_WALLET_KEYSTORE_PATH}')
        if not os.path.isfile(HOT_WALLET_KEYSTORE_PASSWORD_PATH):
            raise ValueError(f"Can't open HOT_WALLET_KEYSTORE_PASSWORD_PATH file. "
                             f'Path: {HOT_WALLET_KEYSTORE_PASSWORD_PATH}')

        with open(HOT_WALLET_KEYSTORE_PATH, 'r', encoding='utf-8') as f:
            keyfile_json = json.load(f)
        with open(HOT_WALLET_KEYSTORE_PASSWORD_PATH, 'r', encoding='utf-8') as f:
            password = f.read().strip()
        key = Account().decrypt(keyfile_json, password)
        return Account().from_key(key)

    raise ValueError('Provide HOT_WALLET_PRIVATE_KEY setting or combination of '
                     'HOT_WALLET_KEYSTORE_PATH and HOT_WALLET_KEYSTORE_PASSWORD_PATH settings')


operator_account = get_operator_account()
