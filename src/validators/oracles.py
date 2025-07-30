import asyncio
import dataclasses
import itertools
import logging
import random
from collections import Counter
from typing import Sequence

from aiohttp import ClientError, ClientSession, ClientTimeout
from eth_typing import ChecksumAddress, HexStr
from sw_utils.common import urljoin
from sw_utils.typings import Bytes32, ProtocolConfig
from web3 import Web3

from src.common.contracts import validators_registry_contract
from src.common.exceptions import NotEnoughOracleApprovalsError
from src.common.execution import get_protocol_config
from src.common.typings import OracleApproval, OraclesApproval, ValidatorType
from src.common.utils import (
    RateLimiter,
    format_error,
    get_current_timestamp,
    process_oracles_approvals,
    warning_verbose,
)
from src.config.settings import (
    ORACLES_CONSOLIDATION_TIMEOUT,
    ORACLES_EXITS_TIMEOUT,
    ORACLES_VALIDATORS_TIMEOUT,
    settings,
)
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import (
    RegistryRootChangedError,
    ValidatorIndexChangedError,
)
from src.validators.execution import (
    get_latest_network_validator_public_keys,
    get_validators_start_index,
)
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.common import get_encrypted_exit_signature_shards
from src.validators.typings import ApprovalRequest, ConsolidationRequest, Validator

logger = logging.getLogger(__name__)


async def poll_validation_approval(
    vault_address: ChecksumAddress,
    keystore: BaseKeystore | None,
    validators: Sequence[Validator],
    validators_manager_signature: HexStr,
) -> tuple[ApprovalRequest, OraclesApproval]:
    """
    Polls oracles for approval of validator registration
    """
    previous_registry_root: Bytes32 | None = None
    oracles_request: ApprovalRequest | None = None
    protocol_config = await get_protocol_config()
    deadline: int | None = None

    approvals_min_interval = 1
    rate_limiter = RateLimiter(approvals_min_interval)

    while True:
        # Keep min interval between requests
        await rate_limiter.ensure_interval()

        # Create new approvals request or reuse the previous one
        current_registry_root = await validators_registry_contract.get_registry_root()
        logger.debug('Fetched validators registry root: %s', Web3.to_hex(current_registry_root))

        current_timestamp = get_current_timestamp()
        if (
            oracles_request is None
            or previous_registry_root is None
            or previous_registry_root != current_registry_root
            or deadline is None
            or deadline <= current_timestamp
        ):
            deadline = current_timestamp + protocol_config.signature_validity_period

            oracles_request = await create_approval_request(
                vault_address=vault_address,
                protocol_config=protocol_config,
                keystore=keystore,
                validators=validators,
                registry_root=current_registry_root,
                deadline=deadline,
                validators_manager_signature=validators_manager_signature,
            )
        previous_registry_root = current_registry_root

        # Send approval requests
        try:
            oracles_approval = await send_approval_requests(protocol_config, oracles_request)
            return oracles_request, oracles_approval
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Not enough oracle approvals for validator registration: %d. Threshold is %d.',
                e.num_votes,
                e.threshold,
            )


async def poll_consolidation_signature(
    protocol_config: ProtocolConfig,
    target_source_public_keys: list[tuple[HexStr, HexStr]],
    vault: ChecksumAddress,
) -> bytes:
    """
    Polls oracles for validator consolidation signature
    """
    approvals_min_interval = 1
    rate_limiter = RateLimiter(approvals_min_interval)
    votes_threshold = protocol_config.validators_threshold
    from_public_keys = []
    to_public_keys = []
    for to_key, from_key in target_source_public_keys:
        from_public_keys.append(from_key)
        to_public_keys.append(to_key)

    consolidation_request = ConsolidationRequest(
        from_public_keys=from_public_keys,
        to_public_keys=to_public_keys,
        vault_address=vault,
    )
    while True:
        # Keep min interval between requests
        await rate_limiter.ensure_interval()

        # Send approval requests
        consolidation_signatures = await _send_consolidation_requests(
            protocol_config, consolidation_request
        )

        if len(consolidation_signatures) < votes_threshold:
            logger.error(
                'Not enough oracle approvals for validator consolidation: %d. Threshold is %d.',
                len(consolidation_signatures),
                votes_threshold,
            )
            continue
        signatures = b''
        for _, signature in sorted(
            consolidation_signatures, key=lambda x: Web3.to_int(hexstr=x[0])
        )[:votes_threshold]:
            signatures += signature
        return signatures


async def send_approval_requests(
    protocol_config: ProtocolConfig, request: ApprovalRequest
) -> OraclesApproval:
    """Requests approval from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = [(oracle.address, oracle.endpoints) for oracle in protocol_config.oracles]

    async with ClientSession(timeout=ClientTimeout(ORACLES_VALIDATORS_TIMEOUT)) as session:
        results = await asyncio.gather(
            *[
                _send_approval_request_to_replicas(
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


# pylint: disable-next=too-many-arguments,too-many-locals
async def create_approval_request(
    vault_address: ChecksumAddress,
    protocol_config: ProtocolConfig,
    keystore: BaseKeystore | None,
    validators: Sequence[Validator],
    registry_root: Bytes32,
    deadline: int,
    validators_manager_signature: HexStr,
) -> ApprovalRequest:
    """Generate validator registration request data"""

    # get next validator index for exit signature
    validators_start_index = await get_validators_start_index()
    logger.debug('Next validator index for exit signature: %d', validators_start_index)

    # get exit signature shards
    request = ApprovalRequest(
        validator_index=validators_start_index,
        vault_address=vault_address,
        validators_root=Web3.to_hex(registry_root),
        public_keys=[],
        deposit_signatures=[],
        public_key_shards=[],
        exit_signature_shards=[],
        deadline=deadline,
        validators_manager_signature=validators_manager_signature,
    )
    if settings.validator_type == ValidatorType.V2:
        request.amounts = []
    for validator_index, validator in enumerate(validators, validators_start_index):
        shards = validator.exit_signature_shards

        if not shards:
            shards = await get_encrypted_exit_signature_shards(
                keystore=keystore,
                public_key=validator.public_key,
                validator_index=validator_index,
                protocol_config=protocol_config,
                exit_signature=validator.exit_signature,
            )

        if not shards:
            logger.warning(
                'Failed to get exit signature shards for validator %s', validator.public_key
            )
            break

        request.public_keys.append(validator.public_key)
        request.deposit_signatures.append(validator.signature)
        request.public_key_shards.append(shards.public_keys)
        request.exit_signature_shards.append(shards.exit_signatures)
        if request.amounts is not None:
            request.amounts.append(validator.amount)
    return request


# pylint: disable=duplicate-code
async def _send_approval_request_to_replicas(
    session: ClientSession, replicas: list[str], payload: dict
) -> OracleApproval:
    last_error = None

    # Shuffling may help if the first endpoint is slower than others
    replicas = random.sample(replicas, len(replicas))

    for endpoint in replicas:
        try:
            return await _send_approval_request(session, endpoint, payload)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('Failed to get response from replicas')


async def _send_approval_request(
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


async def _send_consolidation_requests(
    protocol_config: ProtocolConfig, request: ConsolidationRequest
) -> list[tuple[ChecksumAddress, bytes]]:
    """Requests consolidation signature from all oracles."""
    payload = dataclasses.asdict(request)
    endpoints = [(oracle.address, oracle.endpoints) for oracle in protocol_config.oracles]

    async with ClientSession(timeout=ClientTimeout(ORACLES_CONSOLIDATION_TIMEOUT)) as session:
        results = await asyncio.gather(
            *[
                _send_consolidation_request_to_replicas(
                    session=session, replicas=replicas, payload=payload
                )
                for address, replicas in endpoints
            ],
            return_exceptions=True,
        )

    signatures = []
    failed_endpoints: list[str] = []

    for (address, replicas), result in zip(endpoints, results):
        if isinstance(result, BaseException):
            warning_verbose(
                'All endpoints for oracle %s failed to return consolidate validators request. '
                'Last error: %s',
                address,
                format_error(result),
            )
            failed_endpoints.extend(replicas)
            continue

        signatures.append((address, result))

    logger.info(
        'Fetched signatures for validator consolidation: Received %d out of %d approvals.',
        len(signatures),
        len(protocol_config.oracles),
    )

    if failed_endpoints:
        logger.error(
            'The oracles with endpoints %s have failed to respond.', ', '.join(failed_endpoints)
        )

    return signatures


# pylint: disable=duplicate-code
async def _send_consolidation_request_to_replicas(
    session: ClientSession, replicas: list[str], payload: dict
) -> bytes:
    last_error = None

    # Shuffling may help if the first endpoint is slower than others
    replicas = random.sample(replicas, len(replicas))

    for endpoint in replicas:
        try:
            return await _send_consolidation_request(session, endpoint, payload)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('Failed to get response from replicas')


async def _send_consolidation_request(
    session: ClientSession, endpoint: str, payload: dict
) -> bytes:
    """Requests consolidation signature from single oracle."""
    endpoint = urljoin(endpoint, 'consolidate-validators/')
    logger.debug('send_consolidation_request to %s', endpoint)
    try:
        async with session.post(url=endpoint, json=payload) as response:
            if response.status == 400:
                logger.warning('%s response: %s', endpoint, await response.json())
            response.raise_for_status()
            data = await response.json()
    except (ClientError, asyncio.TimeoutError) as e:
        raise e
    logger.debug('Received response from oracle %s: %s', endpoint, data)
    return Web3.to_bytes(hexstr=data['signature'])


async def poll_active_exits(
    protocol_config: ProtocolConfig,
) -> list[int]:
    """
    Polls oracles for active validator exit indexes
    """
    active_exits = await _fetch_active_exits_requests(protocol_config)

    if len(active_exits) < protocol_config.exit_signature_recover_threshold:
        logger.error(
            'Not enough oracle exits responses: %d. Threshold is %d.',
            len(active_exits),
            protocol_config.exit_signature_recover_threshold,
        )
    # filter only validators with enough amount of exit shares
    exit_indexes = []
    counter = Counter(itertools.chain(*[exits[1] for exits in active_exits]))
    for index, count in counter.items():
        if count >= protocol_config.exit_signature_recover_threshold:
            exit_indexes.append(index)
    return exit_indexes


async def _fetch_active_exits_requests(
    protocol_config: ProtocolConfig,
) -> list[tuple[ChecksumAddress, list[int]]]:
    """Requests active exits from all oracles."""
    endpoints = [(oracle.address, oracle.endpoints) for oracle in protocol_config.oracles]
    async with ClientSession(timeout=ClientTimeout(ORACLES_EXITS_TIMEOUT)) as session:
        results = await asyncio.gather(
            *[
                _fetch_active_exits_from_replicas(
                    session=session,
                    replicas=replicas,
                )
                for address, replicas in endpoints
            ],
            return_exceptions=True,
        )
    exits = []
    failed_endpoints: list[str] = []
    for (address, replicas), result in zip(endpoints, results):
        if isinstance(result, BaseException):
            warning_verbose(
                'All endpoints for oracle %s failed to return active validator exits. '
                'Last error: %s',
                address,
                format_error(result),
            )
            failed_endpoints.extend(replicas)
            continue

        exits.append((address, result))

    if failed_endpoints:
        logger.error(
            'The oracles with endpoints %s have failed to respond.', ', '.join(failed_endpoints)
        )

    return exits


# pylint: disable=duplicate-code
async def _fetch_active_exits_from_replicas(
    session: ClientSession, replicas: list[str]
) -> list[int]:
    last_error = None

    # Shuffling may help if the first endpoint is slower than others
    replicas = random.sample(replicas, len(replicas))

    for endpoint in replicas:
        try:
            return await _fetch_active_exits_request(session, endpoint)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('Failed to get response from replicas')


async def _fetch_active_exits_request(session: ClientSession, endpoint: str) -> list[int]:
    """Requests active exits from single oracle."""
    endpoint = urljoin(endpoint, 'exits/')
    try:
        async with session.get(url=endpoint) as response:
            if response.status == 400:
                logger.warning('%s response: %s', endpoint, await response.json())
            response.raise_for_status()
            data = await response.json()
    except (ClientError, asyncio.TimeoutError) as e:
        raise e
    logger.debug('Received response from oracle %s: %s', endpoint, data)
    return [item['index'] for item in data]
