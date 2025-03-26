import json
import os
from typing import Sequence

from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_account.signers.local import LocalAccount
from eth_typing import HexStr
from web3 import Web3

from src.config import settings
from src.validators.typings import Validator


def load_validators_manager_account() -> LocalAccount:
    keystore_file = settings.validators_manager_key_file
    keystore_password_file = settings.validators_manager_password_file
    if not os.path.isfile(keystore_file):
        raise ValueError(f"Can't open key file. Path: {keystore_file}")
    if not os.path.isfile(keystore_password_file):
        raise ValueError(f"Can't open password file. Path: {keystore_password_file}")

    with open(keystore_file, 'r', encoding='utf-8') as f:
        keyfile_json = json.load(f)
    with open(keystore_password_file, 'r', encoding='utf-8') as f:
        password = f.read().strip()
    key = Account.decrypt(keyfile_json, password)
    return Account().from_key(key)


def get_validators_manager_signature(
    account, validators_registry_root: HexStr, validators: Sequence[Validator]
) -> HexStr:
    encoded_validators = [_encode_validator(v) for v in validators]

    full_message = {
        'primaryType': 'VaultValidators',
        'types': {
            'VaultValidators': [
                {'name': 'validatorsRegistryRoot', 'type': 'bytes32'},
                {'name': 'validators', 'type': 'bytes'},
            ],
        },
        'domain': {
            'name': 'VaultValidators',
            'version': '1',
            'chainId': settings.network_config.CHAIN_ID,
            'verifyingContract': settings.vault,
        },
        'message': {
            'validatorsRegistryRoot': Web3.to_bytes(hexstr=validators_registry_root),
            'validators': b''.join(encoded_validators),
        },
    }

    encoded_message = encode_typed_data(full_message=full_message)
    signed_msg = account.sign_message(encoded_message)

    return HexStr(signed_msg.signature.hex())


def _encode_validator(v: Validator) -> bytes:
    return b''.join(
        [
            Web3.to_bytes(hexstr=v.public_key),
            Web3.to_bytes(hexstr=v.deposit_signature),
            Web3.to_bytes(hexstr=v.deposit_data_root),
        ]
    )
