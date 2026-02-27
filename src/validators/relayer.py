import logging
from typing import Sequence

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature, ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils.common import urljoin
from web3 import Web3
from web3.types import Gwei

from src.common.clients import OPERATOR_USER_AGENT
from src.config.settings import settings
from src.validators.execution import get_validators_start_index
from src.validators.typings import (
    ExitSignatureShards,
    RelayerInfoResponse,
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

        validators = [_parse_validator(v) for v in relayer_response.get('validators') or []]

        validators_manager_signature = _to_hex_or_none(
            relayer_response.get('validators_manager_signature')
        )

        return RelayerValidatorsResponse(
            validators=validators,
            validators_manager_signature=validators_manager_signature,
        )

    async def fund_validators(
        self, validator_fundings: Sequence[tuple[HexStr, Gwei]]
    ) -> RelayerSignatureResponse:
        public_keys, funding_amounts = zip(*validator_fundings)
        relayer_response = await self._fund_validators(
            vault_address=settings.vault,
            public_keys=list(public_keys),
            amounts=list(funding_amounts),
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
        for target, source in target_source_public_keys:
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
        return await self._send_post_request('register', jsn)

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

    async def get_info(self) -> RelayerInfoResponse:
        url = urljoin(settings.relayer_endpoint, 'info')

        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout),
            headers={'User-Agent': OPERATOR_USER_AGENT},
        ) as session:
            resp = await session.get(url)
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            data = await resp.json()
        validators_manager = data.get('validators_manager_address')

        return RelayerInfoResponse(
            network=data['network'],
            validators_manager_address=(
                Web3.to_checksum_address(validators_manager) if validators_manager else None
            ),
        )

    async def _send_post_request(self, endpoint: str, jsn: dict) -> dict:
        url = urljoin(settings.relayer_endpoint, endpoint)
        async with aiohttp.ClientSession(
            timeout=ClientTimeout(settings.relayer_timeout),
            headers={'User-Agent': OPERATOR_USER_AGENT},
        ) as session:
            resp = await session.post(
                url,
                json=jsn,
            )
            if 400 <= resp.status < 500:
                logger.debug('Relayer response: %s', await resp.read())
            resp.raise_for_status()
            return await resp.json()


def _parse_validator(v: dict) -> Validator:
    shards = v.get('oracles_exit_signature_shares')
    exit_signature_shards = (
        ExitSignatureShards(
            public_keys=[add_0x_prefix(pk) for pk in shards['public_keys']],
            exit_signatures=[add_0x_prefix(sig) for sig in shards['encrypted_exit_signatures']],
        )
        if shards
        else None
    )
    return Validator(
        public_key=add_0x_prefix(v['public_key']),
        amount=v['amount'],
        deposit_signature=_to_hex_or_none(v.get('deposit_signature')),
        exit_signature=_to_bls_signature_or_none(v.get('exit_signature')),
        exit_signature_shards=exit_signature_shards,
    )


def _to_hex_or_none(value: str | None) -> HexStr | None:
    return add_0x_prefix(HexStr(value)) if value else None


def _to_bls_signature_or_none(value: str | None) -> BLSSignature | None:
    return BLSSignature(Web3.to_bytes(hexstr=HexStr(value))) if value else None
