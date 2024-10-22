import asyncio
import logging
from typing import cast

import aiohttp
from aiohttp import ClientTimeout
from eth_typing import BLSSignature, HexStr
from eth_utils import add_0x_prefix
from sw_utils.common import urljoin
from web3 import Web3

from src.config.settings import settings
from src.validators.exceptions import MissingDepositDataValidatorsException
from src.validators.execution import (
    get_validators_from_deposit_data,
    get_validators_start_index,
)
from src.validators.signing.common import get_validators_proof
from src.validators.typings import (
    DepositData,
    ExitSignatureShards,
    RelayerTypes,
    RelayerValidatorsResponse,
    Validator,
)
from src.validators.utils import load_deposit_data

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
            'vault': settings.vault,
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
        deposit_data: DepositData | None = None,
    ):
        self.relayer = relayer
        self.deposit_data = deposit_data

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
        deposit_data_validators = await get_validators_from_deposit_data(
            keystore=None,
            deposit_data=cast(DepositData, self.deposit_data),
            count=validators_batch_size,
        )
        if not deposit_data_validators:
            raise MissingDepositDataValidatorsException()

        public_key_to_validator = {v.public_key: v for v in deposit_data_validators}
        public_keys = list(public_key_to_validator.keys())

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

            validator = public_key_to_validator[public_key].copy()
            validator.exit_signature_shards = exit_signature_shards
            validators.append(validator)

        multi_proof = get_validators_proof(
            tree=cast(DepositData, self.deposit_data).tree,
            validators=validators,
        )
        return RelayerValidatorsResponse(
            validators=validators,
            multi_proof=multi_proof,
        )


def create_relayer_adapter() -> RelayerAdapter:
    if settings.relayer_type == RelayerTypes.DVT:
        dvt_relayer = DvtRelayerClient()
        deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
        return RelayerAdapter(dvt_relayer, deposit_data)

    relayer = DefaultRelayerClient()
    return RelayerAdapter(relayer)
