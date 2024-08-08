import abc

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature, HexStr
from eth_utils import add_0x_prefix
from web3 import Web3

from src.config.settings import settings
from src.validators.typings import RelayerValidator, RelayerValidatorsResponse


# pylint:disable-next=too-few-public-methods
class BaseRelayerClient(abc.ABC):
    @abc.abstractmethod
    async def get_validators(
        self, validators_start_index: int, validators_count: int, validators_total: int
    ) -> RelayerValidatorsResponse:
        """
        :param validators_start_index: - validator index for the first validator in a batch.
         Relayer should increment this index for each validator except the first one
        :param validators_count: - number of validators in a batch. Relayer is expected
         to return `validators_count` validators at most
        :param validators_total: - total number of validators supplied by vault assets.
         Should be more than or equal to `validators_count`.
         Relayer may use `validators_total` to create larger portions of validators in background.
        """
        raise NotImplementedError()


# pylint:disable-next=too-few-public-methods
class RelayerClient(BaseRelayerClient):
    async def get_validators(
        self, validators_start_index: int, validators_count: int, validators_total: int
    ) -> RelayerValidatorsResponse:
        jsn = {
            'vault': settings.vault,
            'validators_start_index': validators_start_index,
            'validators_count': validators_count,
            'validators_total': validators_total,
        }
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(f'{settings.relayer_endpoint}/validators', json=jsn)
            resp.raise_for_status()
            resp_json = await resp.json()
            validators = [
                RelayerValidator(
                    public_key=add_0x_prefix(v['public_key']),
                    amount_gwei=v['amount_gwei'],
                    signature=add_0x_prefix(v['deposit_signature']),
                    exit_signature=BLSSignature(
                        Web3.to_bytes(hexstr=add_0x_prefix(v['exit_signature']))
                    ),
                )
                for v in resp_json.get('validators') or []
            ]
            validators_manager_signature = add_0x_prefix(
                resp_json.get('validators_manager_signature') or HexStr('0x')
            )
            return RelayerValidatorsResponse(
                validators=validators,
                validators_manager_signature=validators_manager_signature,
            )
