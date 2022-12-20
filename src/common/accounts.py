from eth_account import Account

from src.config.settings import OPERATOR_PRIVATE_KEY

operator_account = Account().from_key(OPERATOR_PRIVATE_KEY)
