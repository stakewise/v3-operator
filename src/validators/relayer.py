import asyncio
import logging
from typing import cast

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature, HexStr
from eth_utils import add_0x_prefix
from sw_utils.common import urljoin
from web3 import Web3

from src.config.settings import DEPOSIT_AMOUNT_GWEI, settings
from src.validators.exceptions import MissingDepositDataValidatorsException
from src.validators.execution import get_validators_start_index
from src.validators.typings import (
    ExitSignatureShards,
    RelayerTypes,
    RelayerValidatorsResponse,
    Validator,
)
from src.validators.utils import filter_nonregistered_public_keys

logger = logging.getLogger(__name__)


class DefaultRelayerClient:
    async def get_validators(
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


class DvtRelayerClient:
    async def get_info(self) -> dict:
        url = urljoin(settings.relayer_endpoint, 'info')
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.get(url)
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            return await resp.json()

    async def get_validators(self, public_keys: list[HexStr]) -> dict:
        url = urljoin(settings.relayer_endpoint, 'validators')
        jsn = {'public_keys': public_keys}
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(url, json=jsn)
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            return await resp.json()


class RelayerAdapter:
    def __init__(
        self,
        relayer: DefaultRelayerClient | DvtRelayerClient,
        available_public_keys: list[HexStr] | None = None,
    ):
        self.relayer = relayer
        self.available_public_keys = available_public_keys

    async def get_validators(
        self, validators_batch_size: int, validators_total: int
    ) -> RelayerValidatorsResponse:
        if isinstance(self.relayer, DefaultRelayerClient):
            return await self._get_validators_from_default_relayer(
                validators_batch_size, validators_total
            )
        if isinstance(self.relayer, DvtRelayerClient):
            return await self._get_validators_from_dvt_relayer(validators_batch_size)
        raise RuntimeError('Unknown relayer type', type(self.relayer))

    async def _get_validators_from_default_relayer(
        self, validators_batch_size: int, validators_total: int
    ) -> RelayerValidatorsResponse:
        validators_start_index = await get_validators_start_index()
        relayer_response = await cast(DefaultRelayerClient, self.relayer).get_validators(
            validators_start_index, validators_batch_size, validators_total
        )
        validators: list[Validator] = []
        for v in relayer_response.get('validators') or []:
            public_key = add_0x_prefix(v['public_key'])
            deposit_signature = add_0x_prefix(v['deposit_signature'])
            exit_signature = add_0x_prefix(v['exit_signature'])

            validator = Validator(
                public_key=public_key,
                amount_gwei=v['amount_gwei'],
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

    async def _get_validators_from_dvt_relayer(
        self, validators_batch_size: int
    ) -> RelayerValidatorsResponse:
        # build request
        if not self.available_public_keys:
            raise MissingDepositDataValidatorsException()

        public_keys = filter_nonregistered_public_keys(
            available_public_keys=self.available_public_keys,
            count=validators_batch_size,
        )

        if not public_keys:
            raise MissingDepositDataValidatorsException()

        # submit request
        logger.info('Waiting for validators from Relayer...')
        while True:
            relayer_response = await cast(DvtRelayerClient, self.relayer).get_validators(
                public_keys
            )
            if all(v['oracles_exit_signature_shares'] for v in relayer_response['validators']):
                break
            await asyncio.sleep(1)
        logger.debug('relayer_response %s', relayer_response)

        # handle response
        validators: list[Validator] = []
        for v in relayer_response['validators']:
            public_key = add_0x_prefix(v['public_key'])

            exit_signature_shards = None
            if oracle_shares := v['oracles_exit_signature_shares']:
                exit_signatures = [
                    add_0x_prefix(s) for s in oracle_shares['encrypted_exit_signatures']
                ]
                public_keys = [add_0x_prefix(s) for s in oracle_shares['public_keys']]
                exit_signature_shards = ExitSignatureShards(
                    public_keys=public_keys,
                    exit_signatures=exit_signatures,
                )

            validator = Validator(
                public_key=public_key,
                signature=add_0x_prefix(v['deposit_signature']),
                amount_gwei=DEPOSIT_AMOUNT_GWEI,
                exit_signature_shards=exit_signature_shards,
            )
            validators.append(validator)

        return RelayerValidatorsResponse(
            validators=validators,
        )


def create_relayer_adapter() -> RelayerAdapter:
    if settings.relayer_type == RelayerTypes.DVT:
        dvt_relayer = DvtRelayerClient()
        return RelayerAdapter(dvt_relayer)

    relayer = DefaultRelayerClient()
    return RelayerAdapter(relayer)
