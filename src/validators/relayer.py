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
from src.validators.typings import (
    RelayerSignatureResponse,
    RelayerValidatorsResponse,
    Validator,
)

logger = logging.getLogger(__name__)


class RelayerClient:
    async def register_validators(self, amounts: list[Gwei]) -> RelayerValidatorsResponse:
        validators_start_index = await get_validators_start_index()
        relayer_response = await self._register_validators(
            settings.vault, validators_start_index, amounts
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
        self, funding_amounts: dict[HexStr, Gwei]
    ) -> RelayerSignatureResponse:
        relayer_response = await self._fund_validators(
            vault_address=settings.vault,
            public_keys=list(funding_amounts.keys()),
            amounts=list(funding_amounts.values()),
        )

        validators_manager_signature = add_0x_prefix(
            relayer_response.get('validators_manager_signature') or HexStr('0x')
        )
        return RelayerSignatureResponse(
            validators_manager_signature=validators_manager_signature,
        )

    async def withdraw_validators(
        self, withdrawals: dict[HexStr, Gwei]
    ) -> RelayerSignatureResponse:
        relayer_response = await self._withdraw_validators(
            vault_address=settings.vault,
            public_keys=list(withdrawals.keys()),
            amounts=list(withdrawals.values()),
        )
        validators_manager_signature = add_0x_prefix(
            relayer_response.get('validators_manager_signature') or HexStr('0x')
        )
        return RelayerSignatureResponse(
            validators_manager_signature=validators_manager_signature,
        )

    async def consolidate_validators(
        self,
        vault_address: ChecksumAddress,
        target_source_public_keys: list[tuple[HexStr, HexStr]],
    ) -> RelayerSignatureResponse:
        source_public_keys, target_public_keys = [], []
        for source, target in target_source_public_keys:
            source_public_keys.append(source)
            target_public_keys.append(target)
        relayer_response = await self._consolidate_validators(
            vault_address=vault_address,
            source_public_keys=source_public_keys,
            target_public_keys=target_public_keys,
        )
        validators_manager_signature = add_0x_prefix(
            relayer_response.get('validators_manager_signature') or HexStr('0x')
        )
        return RelayerSignatureResponse(
            validators_manager_signature=validators_manager_signature,
        )

    async def _register_validators(
        self,
        vault_address: ChecksumAddress,
        validators_start_index: int,
        amounts: list[Gwei],
    ) -> dict:
        jsn = {
            'vault': vault_address,
            'validators_start_index': validators_start_index,
            'amounts': amounts,
            'validator_type': settings.validator_type.value,
        }
        return await self._send_post_request('validators', jsn)

    async def _fund_validators(
        self, vault_address: ChecksumAddress, public_keys: list[HexStr], amounts: list[Gwei]
    ) -> dict:
        jsn = {
            'vault': vault_address,
            'public_keys': public_keys,
            'amounts': amounts,
        }
        return await self._send_post_request('fund', jsn)

    async def _consolidate_validators(
        self,
        vault_address: ChecksumAddress,
        source_public_keys: list[HexStr],
        target_public_keys: list[HexStr],
    ) -> dict:
        jsn = {
            'vault': vault_address,
            'source_public_keys': source_public_keys,
            'target_public_keys': target_public_keys,
        }
        return await self._send_post_request('consolidate', jsn)

    async def _withdraw_validators(
        self, vault_address: ChecksumAddress, public_keys: list[HexStr], amounts: list[Gwei]
    ) -> dict:
        jsn = {
            'vault': vault_address,
            'public_keys': public_keys,
            'amounts': amounts,
        }
        return await self._send_post_request('withdraw', jsn)

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

    async def _send_post_request(self, endpoint: str, json: dict) -> dict:
        url = urljoin(settings.relayer_endpoint, endpoint)
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout)
        ) as session:
            resp = await session.post(
                url,
                json=json,
            )
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            return await resp.json()
