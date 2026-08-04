from unittest.mock import AsyncMock, patch

import pytest
from eth_typing import HexStr
from sw_utils.tests import faker
from sw_utils.tests.factories import get_mocked_protocol_config
from web3 import Web3

from src.common.exceptions import NotEnoughOracleApprovalsError
from src.common.typings import OraclesApproval
from src.validators.exceptions import ConsolidationError, RegistryRootChangedError
from src.validators.oracles import (
    poll_consolidation_signature,
    poll_validation_approval,
)
from src.validators.typings import ApprovalRequest


@pytest.fixture(autouse=True)
def _no_rate_limit_delay():
    """RateLimiter sleeps between polling iterations; keep the loops instant in tests."""
    with patch('src.common.utils.asyncio.sleep', new=AsyncMock()):
        yield


class TestPollValidationApproval:
    async def test_returns_on_first_success(self):
        """Returns the request/approval pair as soon as send_approval_requests succeeds."""
        registry_root = faker.eth_proof()
        approval_request = _fake_approval_request()
        oracles_approval = OraclesApproval(signatures=b'\x01', ipfs_hash='ipfs', deadline=1)

        with (
            patch(
                'src.validators.oracles.get_protocol_config',
                new=AsyncMock(return_value=get_mocked_protocol_config()),
            ),
            patch(
                'src.validators.oracles.validators_registry_contract.get_registry_root',
                new=AsyncMock(return_value=registry_root),
            ),
            patch(
                'src.validators.oracles.create_approval_request',
                new=AsyncMock(return_value=approval_request),
            ),
            patch(
                'src.validators.oracles.send_approval_requests',
                new=AsyncMock(return_value=oracles_approval),
            ),
        ):
            request, approval = await poll_validation_approval(
                keystore=None,
                validators=[],
                validators_registry_root=registry_root,
                validators_manager_signature=HexStr('0x'),
            )

        assert request is approval_request
        assert approval is oracles_approval

    async def test_raises_after_cap_attempts(self):
        """Re-raises the last NotEnoughOracleApprovalsError once the attempt cap is exhausted."""
        registry_root = faker.eth_proof()
        approval_request = _fake_approval_request()
        error = NotEnoughOracleApprovalsError(num_votes=1, threshold=2)
        send_approval_requests_mock = AsyncMock(side_effect=error)

        with (
            patch(
                'src.validators.oracles.get_protocol_config',
                new=AsyncMock(return_value=get_mocked_protocol_config()),
            ),
            patch(
                'src.validators.oracles.validators_registry_contract.get_registry_root',
                new=AsyncMock(return_value=registry_root),
            ),
            patch(
                'src.validators.oracles.create_approval_request',
                new=AsyncMock(return_value=approval_request),
            ),
            patch('src.validators.oracles.send_approval_requests', new=send_approval_requests_mock),
            patch('src.validators.oracles.ORACLES_APPROVALS_MAX_ATTEMPTS', 3),
        ):
            with pytest.raises(NotEnoughOracleApprovalsError):
                await poll_validation_approval(
                    keystore=None,
                    validators=[],
                    validators_registry_root=registry_root,
                    validators_manager_signature=HexStr('0x'),
                )

        assert send_approval_requests_mock.call_count == 3

    async def test_raises_registry_root_changed_immediately(self):
        """Raises RegistryRootChangedError without ever sending approval requests."""
        passed_registry_root = faker.eth_proof()
        current_registry_root = faker.eth_proof()
        send_approval_requests_mock = AsyncMock()

        with (
            patch(
                'src.validators.oracles.get_protocol_config',
                new=AsyncMock(return_value=get_mocked_protocol_config()),
            ),
            patch(
                'src.validators.oracles.validators_registry_contract.get_registry_root',
                new=AsyncMock(return_value=current_registry_root),
            ),
            patch('src.validators.oracles.send_approval_requests', new=send_approval_requests_mock),
        ):
            with pytest.raises(RegistryRootChangedError):
                await poll_validation_approval(
                    keystore=None,
                    validators=[],
                    validators_registry_root=passed_registry_root,
                    validators_manager_signature=HexStr('0x'),
                )

        send_approval_requests_mock.assert_not_called()


class TestPollConsolidationSignature:
    async def test_raises_after_cap_attempts(self):
        """Raises ConsolidationError once the attempt cap is exhausted below threshold."""
        protocol_config = get_mocked_protocol_config(validators_threshold=2)
        send_requests_mock = AsyncMock(return_value=[])

        with (
            patch('src.validators.oracles._send_consolidation_requests', new=send_requests_mock),
            patch('src.validators.oracles.ORACLES_APPROVALS_MAX_ATTEMPTS', 3),
        ):
            with pytest.raises(ConsolidationError):
                await poll_consolidation_signature(
                    protocol_config=protocol_config,
                    target_public_keys=[faker.validator_public_key()],
                    vault=faker.eth_address(),
                )

        assert send_requests_mock.call_count == 3

    async def test_returns_sorted_truncated_signatures_when_threshold_met(self):
        """Concatenates signatures sorted by oracle address, truncated to the threshold."""
        protocol_config = get_mocked_protocol_config(validators_threshold=2)
        low_address = Web3.to_checksum_address('0x' + '01' * 20)
        mid_address = Web3.to_checksum_address('0x' + '02' * 20)
        high_address = Web3.to_checksum_address('0x' + '03' * 20)
        low_signature = b'\x11'
        mid_signature = b'\x22'
        high_signature = b'\x33'
        # Returned out of order and above threshold, to verify sorting and truncation both apply
        consolidation_signatures = [
            (high_address, high_signature),
            (low_address, low_signature),
            (mid_address, mid_signature),
        ]

        with patch(
            'src.validators.oracles._send_consolidation_requests',
            new=AsyncMock(return_value=consolidation_signatures),
        ):
            signatures = await poll_consolidation_signature(
                protocol_config=protocol_config,
                target_public_keys=[faker.validator_public_key()],
                vault=faker.eth_address(),
            )

        assert signatures == low_signature + mid_signature


def _fake_approval_request() -> ApprovalRequest:
    return ApprovalRequest(
        validator_index=0,
        vault_address=faker.eth_address(),
        validators_root=faker.eth_proof(),
        public_keys=[],
        deposit_signatures=[],
        public_key_shards=[],
        exit_signature_shards=[],
        deadline=0,
        validators_manager_signature=HexStr('0x'),
    )
