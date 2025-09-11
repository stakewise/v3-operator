import logging

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature, ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils.common import urljoin
from web3 import Web3
from web3.types import Gwei

from src.config.settings import settings
from src.validators.execution import get_validators_start_index
from src.validators.typings import RelayerValidatorsResponse, Validator

logger = logging.getLogger(__name__)


class RelayerClient:
    async def register_validators(
        self, vault_address: ChecksumAddress, amounts: list[Gwei]
    ) -> RelayerValidatorsResponse:
        validators_start_index = await get_validators_start_index()
        relayer_response = await self._register_validators(
            vault_address, validators_start_index, amounts
        )
        validators: list[Validator] = []
        for v in relayer_response.get('validators') or []:
            public_key = add_0x_prefix(v['public_key'])
            deposit_signature = add_0x_prefix(v['deposit_signature'])
            exit_signature = add_0x_prefix(v['exit_signature'])

            validator = Validator(
                public_key=public_key,
                amount=v['amount'],
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
        self, vault_address: ChecksumAddress, funding_amounts: dict[HexStr, Gwei]
    ) -> RelayerValidatorsResponse:
        relayer_response = await self._fund_validators(
            vault_address=vault_address,
            public_keys=list(funding_amounts.keys()),
            amount=list(funding_amounts.values()),
        )
        validators: list[Validator] = []
        for v in relayer_response.get('validators') or []:
            public_key = add_0x_prefix(v['public_key'])
            deposit_signature = add_0x_prefix(v['deposit_signature'])
            # deposit_data_root=Web3.to_hex(deposit_data['deposit_data_root']),

            validator = Validator(
                public_key=public_key,
                amount=v['amount'],
                signature=deposit_signature,
            )

            validators.append(validator)

        validators_manager_signature = add_0x_prefix(
            relayer_response.get('validators_manager_signature') or HexStr('0x')
        )
        return RelayerValidatorsResponse(
            validators=validators,
            validators_manager_signature=validators_manager_signature,
        )

    async def _register_validators(
        self,
        vault_address: ChecksumAddress,
        validators_start_index: int,
        amounts: list[Gwei],
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
            'vault': vault_address,
            'validators_start_index': validators_start_index,
            'amounts': amounts,
            'validator_type': settings.validator_type.value,
        }
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(url, json=jsn)
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            return await resp.json()

    async def _fund_validators(
        self, vault_address: ChecksumAddress, public_keys: list[HexStr], amount: list[Gwei]
    ) -> dict:
        url = urljoin(settings.relayer_endpoint, 'fund')
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(
                url,
                json={
                    'vault': vault_address,
                    'public_keys': public_keys,
                    'amounts': amount,
                },
            )
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            return await resp.json()

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
