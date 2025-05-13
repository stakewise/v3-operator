from eth_account.messages import encode_typed_data
from eth_typing import ChecksumAddress, HexStr

from src.common.wallet import hot_wallet
from src.config.settings import settings


def get_validators_manager_signature_withdrawals(
    vault: ChecksumAddress, validator_data: bytes
) -> HexStr:
    full_message = {
        'primaryType': 'VaultValidators',
        'types': {
            'VaultValidators': [
                {'name': 'validators', 'type': 'bytes'},
            ],
        },
        'domain': {
            'name': 'VaultValidators',
            'version': '1',
            'chainId': settings.network_config.CHAIN_ID,
            'verifyingContract': vault,
        },
        'message': {
            'validators': validator_data,
        },
    }

    encoded_message = encode_typed_data(full_message=full_message)
    signed_msg = hot_wallet.sign_message(encoded_message)

    return HexStr(signed_msg.signature.hex())
