import asyncio
import logging
from typing import cast

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature, HexStr
from web3 import Web3

from src.config.settings import RELAYER_TYPE, settings
from src.validators.execution import (
    get_start_validator_index,
    get_validators_from_deposit_data,
)
from src.validators.signing.common import get_validators_proof
from src.validators.typings import (
    DepositData,
    RelayerTypes,
    RelayerValidatorsResponse,
    Validator,
)
from src.validators.utils import load_deposit_data

logger = logging.getLogger(__name__)


class DefaultRelayerClient:
    async def get_validators(self, start_index: int, count: int) -> dict:
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
            return await resp.json()


class DvtRelayerClient:
    async def get_validators(self, public_keys: list[HexStr]) -> dict:
        jsn = {'public_keys': public_keys}
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(f'{settings.relayer_endpoint}/validators', json=jsn)
            resp.raise_for_status()
            return await resp.json()


class RelayerAdapter:
    def __init__(
        self,
        relayer: DefaultRelayerClient | DvtRelayerClient,
        deposit_data: DepositData | None = None,
    ):
        self.relayer = relayer
        self.deposit_data = deposit_data

    async def get_validators(self, count: int) -> RelayerValidatorsResponse:
        if isinstance(self.relayer, DefaultRelayerClient):
            return await self._get_validators_from_default_relayer(count)
        if isinstance(self.relayer, DvtRelayerClient):
            return await self._get_validators_from_dvt_relayer(count)
        raise RuntimeError('Unknown relayer type', type(self.relayer))

    async def _get_validators_from_default_relayer(self, count: int) -> RelayerValidatorsResponse:
        start_index = await get_start_validator_index()
        relayer_response = await cast(DefaultRelayerClient, self.relayer).get_validators(
            start_index, count
        )
        validators = [
            Validator(
                public_key=v['public_key'],
                amount_gwei=v['amount_gwei'],
                signature=v['deposit_signature'],
                exit_signature=BLSSignature(Web3.to_bytes(hexstr=v['exit_signature'])),
            )
            for v in relayer_response['validators']
        ]
        return RelayerValidatorsResponse(
            validators=validators,
            validators_manager_signature=relayer_response['validators_manager_signature'],
        )

    async def _get_validators_from_dvt_relayer(self, count: int) -> RelayerValidatorsResponse:
        # build request
        deposit_data_validators = await get_validators_from_deposit_data(
            keystore=None,
            deposit_data=cast(DepositData, self.deposit_data),
            count=count,
        )
        public_key_to_validator = {v.public_key: v for v in deposit_data_validators}
        public_keys = list(public_key_to_validator.keys())

        # submit request
        logger.info('Waiting for validators from Relayer...')
        while True:
            relayer_response = await cast(DvtRelayerClient, self.relayer).get_validators(
                public_keys
            )
            if all(v['exit_signature'] for v in relayer_response['validators']):
                break
            await asyncio.sleep(1)
        logger.debug('relayer_response %s', relayer_response)

        # handle response
        validators: list[Validator] = []
        for v in relayer_response['validators']:
            validator = public_key_to_validator[v['public_key']].copy()
            validator.exit_signature = BLSSignature(Web3.to_bytes(hexstr=v['exit_signature']))
            validators.append(validator)
        multi_proof = get_validators_proof(
            tree=cast(DepositData, self.deposit_data).tree,
            validators=validators,
        )
        return RelayerValidatorsResponse(
            validators=validators,
            multi_proof=multi_proof,
        )


def create_relayer_adapter():
    if RELAYER_TYPE == RelayerTypes.DVT:
        relayer = DvtRelayerClient()
        deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
        return RelayerAdapter(relayer, deposit_data)

    relayer = DefaultRelayerClient()
    return RelayerAdapter(relayer)
