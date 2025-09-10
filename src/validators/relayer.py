import logging

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature, HexStr
from eth_utils import add_0x_prefix
from sw_utils.common import urljoin
from web3 import Web3
from web3.types import Gwei

from src.config.settings import settings
from src.validators.execution import get_validators_start_index
from src.validators.typings import RelayerValidatorsResponse, Validator

logger = logging.getLogger(__name__)


class RelayerClient:

    async def get_validators(
        self, validators_batch_size: int, validators_total: int
    ) -> RelayerValidatorsResponse:
        validators_start_index = await get_validators_start_index()
        relayer_response = await self._get_validators(
            validators_start_index, validators_batch_size, validators_total
        )
        validators: list[Validator] = []
        for v in relayer_response.get('validators') or []:
            public_key = add_0x_prefix(v['public_key'])
            deposit_signature = add_0x_prefix(v['deposit_signature'])
            exit_signature = add_0x_prefix(v['exit_signature'])

            validator = Validator(
                public_key=public_key,
                amount=v['amount_gwei'],
                signature=deposit_signature,
                exit_signature=BLSSignature(Web3.to_bytes(hexstr=exit_signature)),
            )
            validators.append(validator)

        validators_manager_signature = add_0x_prefix(
            relayer_response.get('validators_manager_signature') or HexStr('0x')
        )
        return RelayerValidatorsResponse(
            validators=validators,
            validators_manager_signature=validators_manager_signature,
        )

    async def fund_validators(
        self, funding_amounts: dict[HexStr, Gwei]
    ) -> RelayerValidatorsResponse:
        relayer_response = await self._fund_validators(funding_amounts)
        validators: list[Validator] = []
        for v in relayer_response.get('validators') or []:
            validator = Validator(
                public_key=add_0x_prefix(v['public_key']),
                amount=v['amount_gwei'],
                signature=add_0x_prefix(v['deposit_signature']),
            )
            validators.append(validator)

        validators_manager_signature = add_0x_prefix(
            relayer_response.get('validators_manager_signature') or HexStr('0x')
        )
        return RelayerValidatorsResponse(
            validators=validators,
            validators_manager_signature=validators_manager_signature,
        )

    async def _get_validators(
        self, validators_start_index: int, validators_batch_size: int, validators_total: int
    ) -> dict:
        """
        :param validators_start_index: - validator index for the first validator in a batch.
         Relayer should increment this index for each validator except the first one
        :param validators_batch_size: - number of validators in a batch. Relayer is expected
         to return `validators_batch_size` validators at most
        :param validators_total: - total number of validators supplied by vault assets.
         Should be more than or equal to `validators_batch_size`.
         Relayer may use `validators_total` to create larger portions of validators in background.
        """
        url = urljoin(settings.relayer_endpoint, 'validators')
        jsn = {
            'validators_start_index': validators_start_index,
            'validators_batch_size': validators_batch_size,
            'validators_total': validators_total,
        }
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(url, json=jsn)
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            return await resp.json()

    async def _fund_validators(self, funding_amounts: dict[HexStr, Gwei]) -> dict:
        url = urljoin(settings.relayer_endpoint, 'fund')
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(url, json=funding_amounts)
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            return await resp.json()
