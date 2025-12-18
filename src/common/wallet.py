import json
from functools import cached_property

from eth_account import Account
from eth_account.account import LocalAccount

from src.config.settings import settings


class Wallet:
    def can_load(self) -> bool:
        try:
            self.account
        except ValueError:
            return False
        return True

    @cached_property
    def account(self) -> LocalAccount:
        if settings.wallet_private_key:
            # pylint: disable-next=no-value-for-parameter
            return Account.from_key(settings.wallet_private_key)

        keystore_file = settings.wallet_file
        keystore_password_file = settings.wallet_password_file
        if not keystore_file.is_file():
            raise ValueError(
                f"Can't open wallet key file. "
                f'Run `create-wallet` command first. '
                f'Path: {keystore_file}'
            )
        if not keystore_password_file.is_file():
            raise ValueError(f"Can't open wallet password file. Path: {keystore_password_file}")

        with open(keystore_file, 'r', encoding='utf-8') as f:
            keyfile_json = json.load(f)
        with open(keystore_password_file, 'r', encoding='utf-8') as f:
            password = f.read().strip()
        key = Account.decrypt(keyfile_json, password)
        return Account().from_key(key)

    def __getattr__(self, item):  # type: ignore
        return getattr(self.account, item)


wallet = Wallet()
