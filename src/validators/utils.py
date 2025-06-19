import asyncio
import dataclasses
import logging
import random
from pathlib import Path
from typing import Sequence

from aiohttp import ClientError, ClientSession, ClientTimeout
from eth_typing import ChecksumAddress, HexAddress, HexStr
from sw_utils import (
    ProtocolConfig,
    get_v1_withdrawal_credentials,
    get_v2_withdrawal_credentials,
)
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import Gwei

from src.common.contracts import validators_registry_contract
from src.common.typings import OracleApproval, OraclesApproval, ValidatorType
from src.common.utils import format_error, process_oracles_approvals, warning_verbose
from src.config.settings import ORACLES_VALIDATORS_TIMEOUT, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import (
    RegistryRootChangedError,
    ValidatorIndexChangedError,
)
from src.validators.execution import get_latest_network_validator_public_keys
from src.validators.keystores.base import BaseKeystore
from src.validators.typings import ApprovalRequest, Validator

logger = logging.getLogger(__name__)


async def send_approval_requests(
    protocol_config: ProtocolConfig, request: ApprovalRequest
) -> OraclesApproval:
    """Requests approval from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = [(oracle.address, oracle.endpoints) for oracle in protocol_config.oracles]

    async with ClientSession(timeout=ClientTimeout(ORACLES_VALIDATORS_TIMEOUT)) as session:
        results = await asyncio.gather(
            *[
                send_approval_request_to_replicas(
                    session=session, replicas=replicas, payload=payload
                )
                for address, replicas in endpoints
            ],
            return_exceptions=True,
        )

    approvals: dict[ChecksumAddress, OracleApproval] = {}
    failed_endpoints: list[str] = []

    for (address, replicas), result in zip(endpoints, results):
        if isinstance(result, BaseException):
            warning_verbose(
                'All endpoints for oracle %s failed to sign validators approval request. '
                'Last error: %s',
                address,
                format_error(result),
            )
            failed_endpoints.extend(replicas)
            continue

        approvals[address] = result

    logger.info(
        'Fetched oracle approvals for validator registration: '
        'deadline=%d, start index=%d. Received %d out of %d approvals.',
        request.deadline,
        request.validator_index,
        len(approvals),
        len(protocol_config.oracles),
    )

    if failed_endpoints:
        logger.error(
            'The oracles with endpoints %s have failed to respond.', ', '.join(failed_endpoints)
        )

    return process_oracles_approvals(approvals, protocol_config.validators_threshold)


# pylint: disable=duplicate-code
async def send_approval_request_to_replicas(
    session: ClientSession, replicas: list[str], payload: dict
) -> OracleApproval:
    last_error = None

    # Shuffling may help if the first endpoint is slower than others
    replicas = random.sample(replicas, len(replicas))

    for endpoint in replicas:
        try:
            return await send_approval_request(session, endpoint, payload)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('Failed to get response from replicas')


async def send_approval_request(
    session: ClientSession, endpoint: str, payload: dict
) -> OracleApproval:
    """Requests approval from single oracle."""
    logger.debug('send_approval_request to %s', endpoint)
    try:
        async with session.post(url=endpoint, json=payload) as response:
            if response.status == 400:
                logger.warning('%s response: %s', endpoint, await response.json())
            response.raise_for_status()
            data = await response.json()
    except (ClientError, asyncio.TimeoutError) as e:
        registry_root = await validators_registry_contract.get_registry_root()
        if Web3.to_hex(registry_root) != payload['validators_root']:
            raise RegistryRootChangedError from e

        latest_public_keys = await get_latest_network_validator_public_keys()
        validator_index = NetworkValidatorCrud().get_next_validator_index(list(latest_public_keys))
        if validator_index != payload['validator_index']:
            raise ValidatorIndexChangedError from e

        raise e
    logger.debug('Received response from oracle %s: %s', endpoint, data)
    return OracleApproval(
        ipfs_hash=data['ipfs_hash'],
        signature=Web3.to_bytes(hexstr=data['signature']),
        deadline=data['deadline'],
    )


async def get_registered_validators(
    keystore: BaseKeystore,
    amounts: list[Gwei],
    vault_address: ChecksumAddress,
    available_public_keys: list[HexStr],
) -> Sequence[Validator]:
    """Returns list of available validators for registration."""
    available_public_keys = filter_nonregistered_public_keys(
        available_public_keys=available_public_keys,
        count=len(amounts),
    )
    validators = []
    for amount, public_key in zip(amounts, available_public_keys):
        deposit_data = await keystore.get_deposit_data(
            public_key=public_key, amount=amount, vault_address=vault_address
        )
        validators.append(
            Validator(
                public_key=Web3.to_hex(deposit_data['pubkey']),
                signature=Web3.to_hex(deposit_data['signature']),
                amount=Gwei(int(deposit_data['amount'])),
                deposit_data_root=Web3.to_hex(deposit_data['deposit_data_root']),
            )
        )

    return validators


async def get_funded_validators(
    keystore: BaseKeystore,
    funding_amounts: dict[HexStr, Gwei],
    vault_address: ChecksumAddress,
) -> list[Validator]:
    public_keys = list(funding_amounts.keys())
    for public_key in public_keys:
        if public_key not in keystore:
            raise RuntimeError(f'Public key {public_key} not found in keystore')
    validators = []
    for public_key, amount in funding_amounts.items():
        deposit_data = await keystore.get_deposit_data(
            public_key=public_key, amount=amount, vault_address=vault_address
        )
        validators.append(
            Validator(
                public_key=Web3.to_hex(deposit_data['pubkey']),
                signature=Web3.to_hex(deposit_data['signature']),
                amount=amount,
                deposit_data_root=Web3.to_hex(deposit_data['deposit_data_root']),
            )
        )
    return validators


def filter_nonregistered_public_keys(
    available_public_keys: list[HexStr],
    count: int,
) -> list[HexStr]:
    public_keys: list[HexStr] = []
    for public_key in available_public_keys:
        if NetworkValidatorCrud().is_validator_registered(public_key):
            continue
        public_keys.append(public_key)
        if len(public_keys) >= count:
            break

    return public_keys


def load_public_keys(public_keys_file: Path) -> list[HexStr]:
    """Loads available public keys from file."""
    with open(public_keys_file, 'r', encoding='utf-8') as f:
        public_keys = [HexStr(line.rstrip()) for line in f]

    return public_keys


def save_public_keys(filename: Path, public_keys: list[HexStr]) -> None:
    filename.parent.mkdir(parents=True, exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        for public_key in public_keys:
            f.write(f'{public_key}\n')


def get_withdrawal_credentials(vault_address: HexAddress) -> Bytes32:
    """Returns withdrawal credentials based on the vault address and validator type."""
    if settings.validator_type == ValidatorType.V1:
        return get_v1_withdrawal_credentials(vault_address)
    return get_v2_withdrawal_credentials(vault_address)
