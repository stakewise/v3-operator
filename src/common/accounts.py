import json
import os.path

from eth_account import Account
from eth_account.account import LocalAccount

from src.config.settings import (
    OPERATOR_KEYSTORE_PASSWORD_PATH,
    OPERATOR_KEYSTORE_PATH,
    OPERATOR_PRIVATE_KEY,
)


def get_operator_account() -> LocalAccount:
    if OPERATOR_PRIVATE_KEY:
        return Account().from_key(OPERATOR_PRIVATE_KEY)

    if OPERATOR_KEYSTORE_PATH and OPERATOR_KEYSTORE_PASSWORD_PATH:
        if not os.path.isfile(OPERATOR_KEYSTORE_PATH):
            raise ValueError(f"Can't open OPERATOR_KEYSTORE_PATH file. "
                             f' Path: {OPERATOR_KEYSTORE_PATH}')
        if not os.path.isfile(OPERATOR_KEYSTORE_PASSWORD_PATH):
            raise ValueError(f"Can't open OPERATOR_KEYSTORE_PASSWORD_PATH file. "
                             f'Path: {OPERATOR_KEYSTORE_PASSWORD_PATH}')

        with open(OPERATOR_KEYSTORE_PATH, 'r', encoding='utf-8') as f:
            keyfile_json = json.load(f)
        with open(OPERATOR_KEYSTORE_PASSWORD_PATH, 'r', encoding='utf-8') as f:
            password = f.read().strip()
        key = Account().decrypt(keyfile_json, password)
        return Account().from_key(key)

    raise ValueError('Provide OPERATOR_PRIVATE_KEY setting or combination of '
                     'OPERATOR_KEYSTORE_PATH and OPERATOR_KEYSTORE_PASSWORD_PATH settings')


operator_account = get_operator_account()
