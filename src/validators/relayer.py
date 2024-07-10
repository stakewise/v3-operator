import abc

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature
from multiproof import MultiProof
from web3 import Web3

from src.config.settings import settings
from src.validators.signing.common import encode_tx_validator_list
from src.validators.typings import RelayerValidatorsResponse, Validator


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
            validators = []
            for validator_item in resp_json['validators']:
                validator = Validator(
                    public_key=validator_item['public_key'],
                    amount_gwei=validator_item['amount_gwei'],
                    signature=validator_item['deposit_signature'],
                    exit_signature=BLSSignature(
                        Web3.to_bytes(hexstr=validator_item['exit_signature'])
                    ),
                )
                validators.append(validator)

            multi_proof: MultiProof[tuple[bytes, int]] | None = None
            if resp_json['proof'] is not None:
                tx_validators = encode_tx_validator_list(validators)
                leaves = list(zip(tx_validators, resp_json['proof_indexes']))
                multi_proof = MultiProof(
                    leaves=leaves, proof=resp_json['proof'], proof_flags=resp_json['proof_flags']
                )
            return RelayerValidatorsResponse(
                validators=validators, validators_manager_signature=None, multi_proof=multi_proof
            )
