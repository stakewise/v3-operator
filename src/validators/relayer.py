import abc

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature
from web3 import Web3

from src.config.settings import settings
from src.validators.typings import RelayerValidator, RelayerValidatorsResponse


# pylint:disable-next=too-few-public-methods
class BaseRelayerClient(abc.ABC):
    @abc.abstractmethod
    async def get_validators(self, start_index: int, count: int) -> RelayerValidatorsResponse:
        raise NotImplementedError()


# pylint:disable-next=too-few-public-methods
class RelayerClient(BaseRelayerClient):
    async def get_validators(self, start_index: int, count: int) -> RelayerValidatorsResponse:
        jsn = {
            'vault': settings.vault,
            'validator_index': start_index,
            'validators_count': count,
        }
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(f'{settings.relayer_endpoint}/validators', json=jsn)
            resp.raise_for_status()
            resp_json = await resp.json()
            validators = [
                RelayerValidator(
                    public_key=v['public_key'],
                    amount_gwei=v['amount_gwei'],
                    signature=v['deposit_signature'],
                    withdrawal_address=v.get('withdrawal_address'),
                    exit_signature=BLSSignature(Web3.to_bytes(hexstr=v['exit_signature'])),
                )
                for v in resp_json['validators']
            ]
            return RelayerValidatorsResponse(
                validators=validators,
                validators_manager_signature=resp_json['validators_manager_signature'],
            )
