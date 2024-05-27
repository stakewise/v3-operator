from typing import Sequence

from eth_account.messages import encode_typed_data
from eth_typing import HexStr
from web3 import Web3

from src.common.contracts import validators_registry_contract
from src.common.wallet import hot_wallet
from src.config.networks import GNO_NETWORKS
from src.config.settings import settings
from src.validators.typings import Validator


async def get_validators_manager_signature(validators: Sequence[Validator]) -> HexStr:
    validators_registry_root = await validators_registry_contract.get_registry_root()

    validators_checker_type_name = 'EthValidatorsChecker'
    if settings.network in GNO_NETWORKS:
        validators_checker_type_name = 'GnoValidatorsChecker'

    concat_pubkeys = b''.join(Web3.to_bytes(hexstr=v.public_key) for v in validators)

    full_message = {
        'primaryType': validators_checker_type_name,
        'types': {
            validators_checker_type_name: [
                {'name': 'validatorsRegistryRoot', 'type': 'bytes32'},
                {'name': 'vault', 'type': 'address'},
                {'name': 'validators', 'type': 'bytes'},
            ],
        },
        'domain': {
            'name': validators_checker_type_name,
            'version': '1',
            'chainId': settings.network_config.CHAIN_ID,
            'verifyingContract': settings.network_config.VALIDATORS_CHECKER_CONTRACT_ADDRESS,
        },
        'message': {
            'validatorsRegistryRoot': validators_registry_root,
            'vault': settings.vault,
            'validators': concat_pubkeys,
        },
    }

    encoded_message = encode_typed_data(full_message=full_message)
    signed_msg = hot_wallet.sign_message(encoded_message)

    return signed_msg.signature.hex()
