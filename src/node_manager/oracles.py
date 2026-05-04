import asyncio
import dataclasses
import logging
import random
from collections import defaultdict
from typing import Callable, Sequence, TypeVar

from aiohttp import ClientError, ClientSession, ClientTimeout
from eth_account.messages import encode_defunct
from eth_typing import ChecksumAddress, HexStr
from sw_utils.common import urljoin
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import Wei

from src.common.contracts import validators_registry_contract
from src.common.exceptions import (
    InvalidOraclesRequestError,
    NotEnoughOracleApprovalsError,
)
from src.common.utils import (
    RateLimiter,
    format_error,
    get_current_timestamp,
    warning_verbose,
)
from src.common.wallet import wallet
from src.config.settings import ORACLES_VALIDATORS_TIMEOUT
from src.node_manager.typings import (
    EligibleOperator,
    NodeManagerApprovalRequest,
    NodeManagerFundingApproval,
    NodeManagerFundingRequest,
    NodeManagerRegistrationApproval,
    NodeManagerRegistrationOraclesApproval,
)
from src.validators.execution import get_validators_start_index
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.common import get_encrypted_exit_signature_shards
from src.validators.typings import Validator

T = TypeVar('T')

logger = logging.getLogger(__name__)

ELIGIBLE_OPERATORS_PATH = '/nodes-manager/eligible-operators'
REGISTER_VALIDATORS_PATH = '/nodes-manager/register-validators'
FUND_VALIDATORS_PATH = '/nodes-manager/fund-validators'

# Eligible operators polling


async def poll_eligible_operators(
    protocol_config: ProtocolConfig,
) -> list[EligibleOperator]:
    """Poll a random oracle for the list of eligible operators."""
    oracles = list(protocol_config.oracles)
    random.shuffle(oracles)  # nosec

    async with ClientSession(timeout=ClientTimeout(ORACLES_VALIDATORS_TIMEOUT)) as session:
        for oracle in oracles:
            try:
                return await _fetch_eligible_from_replicas(
                    session=session, replicas=oracle.endpoints
                )
            except (ClientError, asyncio.TimeoutError, RuntimeError) as e:
                warning_verbose(
                    'Oracle %s failed to return eligible operators: %s',
                    oracle.address,
                    format_error(e),
                )

    logger.error('All oracle endpoints failed to return eligible operators.')
    return []


async def _fetch_eligible_from_replicas(
    session: ClientSession,
    replicas: list[str],
) -> list[EligibleOperator]:
    """Try replicas in random order, return first success."""
    last_error: BaseException | None = None
    replicas = random.sample(replicas, len(replicas))  # nosec

    for endpoint in replicas:
        try:
            return await _fetch_eligible_operators(session, endpoint)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('No replicas available')


async def _fetch_eligible_operators(
    session: ClientSession,
    endpoint: str,
) -> list[EligibleOperator]:
    """Fetch eligible operators from a single oracle endpoint."""
    url = urljoin(endpoint, ELIGIBLE_OPERATORS_PATH)
    logger.debug('Fetching eligible operators from %s', url)

    async with session.get(url=url) as response:
        if response.status == 400:
            logger.warning('%s response: %s', url, await response.json())
        response.raise_for_status()
        data: list[dict] = await response.json()

    return [
        EligibleOperator(
            address=Web3.to_checksum_address(item['address']),
            amount=Wei(int(item['amount'])),
        )
        for item in data
    ]


async def poll_registration_approval(
    keystore: BaseKeystore,
    validators: Sequence[Validator],
    operator_address: ChecksumAddress,
    protocol_config: ProtocolConfig,
) -> tuple[NodeManagerApprovalRequest, NodeManagerRegistrationOraclesApproval]:
    """Poll oracles until registration approval is obtained."""
    oracles_request: NodeManagerApprovalRequest | None = None
    deadline: int | None = None
    validators_registry_root = await validators_registry_contract.get_registry_root()

    approvals_min_interval = 1
    rate_limiter = RateLimiter(approvals_min_interval)

    while True:
        await rate_limiter.ensure_interval()

        current_registry_root = await validators_registry_contract.get_registry_root()
        if current_registry_root != validators_registry_root:
            validators_registry_root = current_registry_root
            oracles_request = None

        current_timestamp = get_current_timestamp()
        if oracles_request is None or deadline is None or deadline <= current_timestamp:
            deadline = current_timestamp + protocol_config.signature_validity_period

            oracles_request = await create_approval_request(
                protocol_config=protocol_config,
                keystore=keystore,
                validators=validators,
                registry_root=current_registry_root,
                deadline=deadline,
                operator_address=operator_address,
            )

        try:
            raw_approvals = await send_registration_requests(protocol_config, oracles_request)
            oracles_approval = process_registration_approvals(
                raw_approvals, protocol_config.validators_threshold
            )
            return oracles_request, oracles_approval
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Not enough oracle approvals for community vault registration: %d.'
                ' Threshold is %d.',
                e.num_votes,
                e.threshold,
            )
        except InvalidOraclesRequestError:
            logger.error('All oracles failed to respond for community vault registration')


# Registration approval polling


# pylint: disable-next=too-many-arguments
async def create_approval_request(
    protocol_config: ProtocolConfig,
    keystore: BaseKeystore,
    validators: Sequence[Validator],
    registry_root: HexStr,
    deadline: int,
    operator_address: ChecksumAddress,
) -> NodeManagerApprovalRequest:
    """Build a NodesManager approval request with exit signature shards."""
    validators_start_index = await get_validators_start_index()
    logger.debug(
        'Next validator index for community vault exit signature: %d', validators_start_index
    )

    request = NodeManagerApprovalRequest(
        validator_index=validators_start_index,
        operator_address=operator_address,
        validators_root=registry_root,
        public_keys=[],
        deposit_signatures=[],
        public_key_shards=[],
        exit_signature_shards=[],
        deadline=deadline,
        amounts=[],
        validators_manager_signature=_sign_deadline(deadline),
    )

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

        if validator.deposit_signature is None:
            raise ValueError('Deposit signature is required for validator')

        request.public_keys.append(validator.public_key)
        request.deposit_signatures.append(validator.deposit_signature)
        request.public_key_shards.append(shards.public_keys)
        request.exit_signature_shards.append(shards.exit_signatures)
        request.amounts.append(validator.amount)

    if not request.public_keys:
        raise ValueError(
            'Failed to build validator registration request:'
            ' no validators with valid exit signature shards'
        )

    return request


# Funding approval polling


async def poll_funding_approval(
    validators: Sequence[Validator],
    operator_address: ChecksumAddress,
    protocol_config: ProtocolConfig,
) -> list[HexStr]:
    """Poll oracles until funding approval is obtained."""
    deadline: int | None = None
    request: NodeManagerFundingRequest | None = None

    approvals_min_interval = 1
    rate_limiter = RateLimiter(approvals_min_interval)

    while True:
        await rate_limiter.ensure_interval()

        current_timestamp = get_current_timestamp()
        if request is None or deadline is None or deadline <= current_timestamp:
            deadline = current_timestamp + protocol_config.signature_validity_period
            request = create_funding_request(
                validators=validators,
                operator_address=operator_address,
                deadline=deadline,
            )

        try:
            raw_approvals = await send_funding_requests(protocol_config, request)
            return process_funding_approvals(raw_approvals, protocol_config.validators_threshold)
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Not enough oracle approvals for community vault funding: %d. Threshold is %d.',
                e.num_votes,
                e.threshold,
            )


def create_funding_request(
    validators: Sequence[Validator],
    operator_address: ChecksumAddress,
    deadline: int,
) -> NodeManagerFundingRequest:
    """Build a NodesManager funding request for validator top-ups."""

    request = NodeManagerFundingRequest(
        operator_address=operator_address,
        public_keys=[],
        amounts=[],
        deposit_signatures=[],
        deadline=deadline,
        validators_manager_signature=_sign_deadline(deadline),
    )

    for validator in validators:
        if validator.deposit_signature is None:
            raise ValueError('Deposit signature is required for validator')

        request.public_keys.append(validator.public_key)
        request.deposit_signatures.append(validator.deposit_signature)
        request.amounts.append(validator.amount)

    return request


# Generic oracle request helpers


async def send_registration_requests(
    protocol_config: ProtocolConfig,
    request: NodeManagerApprovalRequest,
) -> dict[ChecksumAddress, NodeManagerRegistrationApproval]:
    """Request registration approval from all oracles in parallel."""
    return await _send_oracle_requests(
        protocol_config,
        dataclasses.asdict(request),
        REGISTER_VALIDATORS_PATH,
        _parse_registration_response,
    )


async def send_funding_requests(
    protocol_config: ProtocolConfig,
    request: NodeManagerFundingRequest,
) -> dict[ChecksumAddress, NodeManagerFundingApproval]:
    """Request funding approval from all oracles in parallel."""
    return await _send_oracle_requests(
        protocol_config,
        dataclasses.asdict(request),
        FUND_VALIDATORS_PATH,
        _parse_funding_response,
    )


def _parse_funding_response(data: dict) -> NodeManagerFundingApproval:
    """Parse oracle response for funding (single Node Manager signature)."""
    return NodeManagerFundingApproval(
        nodes_manager_signature=HexStr(data['nodes_manager_signature']),
    )


def _parse_registration_response(data: dict) -> NodeManagerRegistrationApproval:
    """Parse oracle response containing both keeper and Nodes Manager signatures."""
    keeper_params = data['keeper_params']
    return NodeManagerRegistrationApproval(
        keeper_signature=HexStr(keeper_params['signature']),
        nodes_manager_signature=HexStr(data['nodes_manager_signature']),
        ipfs_hash=keeper_params['ipfs_hash'],
        deadline=keeper_params['deadline'],
    )


def process_registration_approvals(
    approvals: dict[ChecksumAddress, NodeManagerRegistrationApproval],
    votes_threshold: int,
) -> NodeManagerRegistrationOraclesApproval:
    """Combine registration approvals into separate keeper and Nodes Manager signature blobs."""
    candidates: dict[
        tuple[str, int], list[tuple[ChecksumAddress, NodeManagerRegistrationApproval]]
    ] = defaultdict(list)
    for address, approval in approvals.items():
        candidates[approval.ipfs_hash, approval.deadline].append((address, approval))

    if not candidates:
        raise InvalidOraclesRequestError()

    winner = max(candidates, key=lambda x: len(candidates[x]))
    votes = candidates[winner]
    if len(votes) < votes_threshold:
        raise NotEnoughOracleApprovalsError(num_votes=len(votes), threshold=votes_threshold)

    sorted_votes = sorted(votes, key=lambda x: Web3.to_int(hexstr=x[0]))[:votes_threshold]

    keeper_signatures: list[HexStr] = []
    signatures: list[HexStr] = []
    for _, approval in sorted_votes:
        keeper_signatures.append(approval.keeper_signature)
        signatures.append(approval.nodes_manager_signature)

    return NodeManagerRegistrationOraclesApproval(
        nodes_manager_signatures=signatures,
        keeper_signatures=keeper_signatures,
        ipfs_hash=winner[0],
        deadline=winner[1],
    )


def process_funding_approvals(
    approvals: dict[ChecksumAddress, NodeManagerFundingApproval],
    votes_threshold: int,
) -> list[HexStr]:
    """Combine funding approvals into sorted Node Manager signature list."""
    if not approvals:
        raise InvalidOraclesRequestError()

    if len(approvals) < votes_threshold:
        raise NotEnoughOracleApprovalsError(num_votes=len(approvals), threshold=votes_threshold)

    sorted_oracles = sorted(approvals.items(), key=lambda x: Web3.to_int(hexstr=x[0]))[
        :votes_threshold
    ]

    signatures: list[HexStr] = []
    for _, approval in sorted_oracles:
        signatures.append(approval.nodes_manager_signature)

    return signatures


async def _send_oracle_requests(
    protocol_config: ProtocolConfig,
    payload: dict,
    path: str,
    parser: Callable[[dict], T],
) -> dict[ChecksumAddress, T]:
    """Send a NodesManager request to all oracles in parallel and collect approvals."""
    endpoints = [(oracle.address, oracle.endpoints) for oracle in protocol_config.oracles]

    async with ClientSession(timeout=ClientTimeout(ORACLES_VALIDATORS_TIMEOUT)) as session:
        results = await asyncio.gather(
            *[
                _send_request_to_replicas(
                    session=session,
                    replicas=replicas,
                    payload=payload,
                    path=path,
                    parser=parser,
                )
                for _, replicas in endpoints
            ],
            return_exceptions=True,
        )

    approvals: dict[ChecksumAddress, T] = {}
    failed_endpoints: list[str] = []

    for (address, replicas), result in zip(endpoints, results):
        if isinstance(result, BaseException):
            warning_verbose(
                'All endpoints for oracle %s failed to sign community vault request (%s). '
                'Last error: %s',
                address,
                path,
                format_error(result),
            )
            failed_endpoints.extend(replicas)
            continue

        approvals[address] = result

    logger.info(
        'Fetched oracle approvals for community vault request %s: '
        'deadline=%d. Received %d out of %d approvals.',
        path,
        payload.get('deadline', 0),
        len(approvals),
        len(protocol_config.oracles),
    )

    if failed_endpoints:
        logger.error(
            'The oracles with endpoints %s have failed to respond.', ', '.join(failed_endpoints)
        )

    return approvals


# pylint: disable=duplicate-code
async def _send_request_to_replicas(
    session: ClientSession,
    replicas: list[str],
    payload: dict,
    path: str,
    parser: Callable[[dict], T],
) -> T:
    """Try replicas in random order, return first success."""
    last_error: BaseException | None = None
    replicas = random.sample(replicas, len(replicas))  # nosec

    for endpoint in replicas:
        try:
            return await _send_request(session, endpoint, payload, path, parser)
        except (ClientError, asyncio.TimeoutError) as e:
            warning_verbose('%s for endpoint %s', format_error(e), endpoint)
            last_error = e

    if last_error:
        raise last_error

    raise RuntimeError('Failed to get response from replicas')


async def _send_request(
    session: ClientSession,
    endpoint: str,
    payload: dict,
    path: str,
    parser: Callable[[dict], T],
) -> T:
    """Send a NodesManager POST request to a single oracle endpoint."""
    url = urljoin(endpoint, path)
    logger.debug('Sending community vault request to %s', url)

    async with session.post(url=url, json=payload) as response:
        if response.status == 400:
            logger.warning('%s response: %s', url, await response.json())
        response.raise_for_status()
        data = await response.json()

    logger.debug('Received community vault response from %s: %s', url, data)
    return parser(data)


def _sign_deadline(deadline: int) -> HexStr:
    """EIP-191 personal_sign of the deadline timestamp."""
    message = encode_defunct(primitive=deadline.to_bytes(32, byteorder='big'))
    return HexStr(wallet.sign_message(message).signature.hex())
