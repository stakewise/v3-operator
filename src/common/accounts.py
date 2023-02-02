import json
import os.path

from eth_account import Account
from eth_account.account import LocalAccount

from src.config.settings import (
    WALLET_KEYSTORE_PASSWORD_PATH,
    WALLET_KEYSTORE_PATH,
    WALLET_PRIVATE_KEY,
)


def get_operator_account() -> LocalAccount:
    if WALLET_PRIVATE_KEY:
        return Account().from_key(WALLET_PRIVATE_KEY)

    if WALLET_KEYSTORE_PATH and WALLET_KEYSTORE_PASSWORD_PATH:
        if not os.path.isfile(WALLET_KEYSTORE_PATH):
            raise ValueError(f"Can't open WALLET_KEYSTORE_PATH file. "
                             f' Path: {WALLET_KEYSTORE_PATH}')
        if not os.path.isfile(WALLET_KEYSTORE_PASSWORD_PATH):
            raise ValueError(f"Can't open WALLET_KEYSTORE_PASSWORD_PATH file. "
                             f'Path: {WALLET_KEYSTORE_PASSWORD_PATH}')

        with open(WALLET_KEYSTORE_PATH, 'r', encoding='utf-8') as f:
            keyfile_json = json.load(f)
        with open(WALLET_KEYSTORE_PASSWORD_PATH, 'r', encoding='utf-8') as f:
            password = f.read().strip()
        key = Account().decrypt(keyfile_json, password)
        return Account().from_key(key)

    raise ValueError('Provide WALLET_PRIVATE_KEY setting or combination of '
                     'WALLET_KEYSTORE_PATH and WALLET_KEYSTORE_PASSWORD_PATH settings')


operator_account = get_operator_account()
