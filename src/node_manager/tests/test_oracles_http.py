import pytest
from aioresponses import aioresponses
from eth_typing import HexStr
from sw_utils.tests.factories import faker, get_mocked_protocol_config
from sw_utils.typings import Oracle, ProtocolConfig
from web3 import Web3
from web3.types import Wei

from src.common.tests.utils import ether_to_gwei
from src.node_manager.oracles import (
    poll_eligible_operators,
    send_funding_requests,
    send_registration_requests,
)
from src.node_manager.typings import (
    NodeManagerApprovalRequest,
    NodeManagerFundingRequest,
)

# --- poll_eligible_operators tests ---


@pytest.mark.usefixtures('fake_settings')
class TestPollEligibleOperators:
    async def test_returns_eligible_operators(self) -> None:
        config = _make_protocol_config([['http://oracle1']])
        operator_address = faker.eth_address()
        response_data = [
            {'address': operator_address.lower(), 'amount': Web3.to_wei(32, 'ether')},
        ]

        with aioresponses() as m:
            m.get(
                'http://oracle1/nodes-manager/eligible-operators',
                payload=response_data,
            )
            result = await poll_eligible_operators(config)

        assert len(result) == 1
        assert result[0].address == operator_address
        assert result[0].amount == Web3.to_wei(32, 'ether')

    async def test_returns_empty_on_all_failures(self) -> None:
        config = _make_protocol_config([['http://oracle1']])

        with aioresponses() as m:
            m.get(
                'http://oracle1/nodes-manager/eligible-operators',
                status=500,
            )
            result = await poll_eligible_operators(config)

        assert result == []

    async def test_falls_back_to_next_oracle(self) -> None:
        config = _make_protocol_config(
            [['http://oracle1'], ['http://oracle2']],
        )
        address = faker.eth_address().lower()
        response_data = [
            {'address': address, 'amount': 100},
        ]

        with aioresponses() as m:
            m.get('http://oracle1/nodes-manager/eligible-operators', status=500)
            m.get('http://oracle2/nodes-manager/eligible-operators', payload=response_data)
            result = await poll_eligible_operators(config)

        assert len(result) == 1
        assert result[0].address == Web3.to_checksum_address(address)
        assert result[0].amount == Wei(100)

    async def test_replica_fallback(self) -> None:
        """If first replica fails, tries the next one."""
        config = _make_protocol_config([['http://replica1', 'http://replica2']])
        address = faker.eth_address().lower()
        response_data = [{'address': address, 'amount': 100}]

        with aioresponses() as m:
            m.get('http://replica1/nodes-manager/eligible-operators', status=500)
            m.get('http://replica2/nodes-manager/eligible-operators', payload=response_data)
            result = await poll_eligible_operators(config)

        assert len(result) == 1
        assert result[0].address == Web3.to_checksum_address(address)
        assert result[0].amount == Wei(100)


# --- send_registration_requests tests ---


@pytest.mark.usefixtures('fake_settings')
class TestSendRegistrationRequests:
    async def test_collects_approvals(self) -> None:
        config = _make_protocol_config(
            [['http://oracle1'], ['http://oracle2']],
            threshold=2,
        )
        request = _make_registration_request()
        keeper_signature = faker.account_signature()
        signature = faker.account_signature()

        oracle_response = {
            'keeper_params': {
                'signature': keeper_signature,
                'ipfs_hash': faker.ipfs_hash(),
                'deadline': 1000,
            },
            'nodes_manager_signature': signature,
        }

        with aioresponses() as m:
            m.post(
                'http://oracle1/nodes-manager/register-validators',
                payload=oracle_response,
            )
            m.post(
                'http://oracle2/nodes-manager/register-validators',
                payload=oracle_response,
            )
            approvals = await send_registration_requests(config, request)

        assert len(approvals) == 2
        for approval in approvals.values():
            assert approval.keeper_signature == keeper_signature
            assert approval.nodes_manager_signature == signature

    async def test_partial_failure(self) -> None:
        """One oracle fails, the other succeeds — still returns what we got."""
        config = _make_protocol_config(
            [['http://oracle1'], ['http://oracle2']],
            threshold=1,
        )
        request = _make_registration_request()
        keeper_signature = faker.account_signature()
        signature = faker.account_signature()
        oracle_response = {
            'keeper_params': {
                'signature': keeper_signature,
                'ipfs_hash': faker.ipfs_hash(),
                'deadline': 1000,
            },
            'nodes_manager_signature': signature,
        }

        with aioresponses() as m:
            m.post('http://oracle1/nodes-manager/register-validators', status=500)
            m.post(
                'http://oracle2/nodes-manager/register-validators',
                payload=oracle_response,
            )
            approvals = await send_registration_requests(config, request)

        assert len(approvals) == 1
        approval = next(iter(approvals.values()))
        assert approval.keeper_signature == keeper_signature
        assert approval.nodes_manager_signature == signature


# --- send_funding_requests tests ---


@pytest.mark.usefixtures('fake_settings')
class TestSendFundingRequests:
    async def test_collects_approvals(self) -> None:
        config = _make_protocol_config(
            [['http://oracle1'], ['http://oracle2']],
            threshold=2,
        )
        request = _make_funding_request()
        signature = faker.account_signature()

        oracle_response = {'nodes_manager_signature': signature}

        with aioresponses() as m:
            m.post(
                'http://oracle1/nodes-manager/fund-validators',
                payload=oracle_response,
            )
            m.post(
                'http://oracle2/nodes-manager/fund-validators',
                payload=oracle_response,
            )
            approvals = await send_funding_requests(config, request)

        assert len(approvals) == 2

    async def test_partial_failure(self) -> None:
        """One oracle fails, the other succeeds — still returns what we got."""
        config = _make_protocol_config(
            [['http://oracle1'], ['http://oracle2']],
            threshold=1,
        )
        request = _make_funding_request()
        oracle_response = {'nodes_manager_signature': faker.account_signature()}

        with aioresponses() as m:
            m.post('http://oracle1/nodes-manager/fund-validators', status=500)
            m.post(
                'http://oracle2/nodes-manager/fund-validators',
                payload=oracle_response,
            )
            approvals = await send_funding_requests(config, request)

        assert len(approvals) == 1


# --- Helpers ---

_ORACLE_PUBKEYS: list[HexStr] = [faker.account_public_key() for _ in range(9)]


def _make_protocol_config(
    oracle_endpoints: list[list[str]],
    threshold: int = 2,
) -> ProtocolConfig:
    oracles = []
    for i, endpoints in enumerate(oracle_endpoints):
        oracles.append(
            Oracle(
                public_key=_ORACLE_PUBKEYS[i],
                endpoints=endpoints,
            )
        )
    return get_mocked_protocol_config(
        oracles=oracles,
        validators_threshold=threshold,
        signature_validity_period=60,
        validators_approval_batch_limit=10,
    )


def _make_funding_request() -> NodeManagerFundingRequest:
    return NodeManagerFundingRequest(
        operator_address=faker.eth_address(),
        public_keys=[faker.validator_public_key()],
        amounts=[ether_to_gwei(32)],
        deadline=1000,
        validators_manager_signature=faker.account_signature(),
    )


def _make_registration_request() -> NodeManagerApprovalRequest:
    return NodeManagerApprovalRequest(
        validator_index=0,
        operator_address=faker.eth_address(),
        validators_root=faker.merkle_root(),
        public_keys=[faker.validator_public_key()],
        deposit_signatures=[faker.validator_signature()],
        public_key_shards=[[faker.validator_public_key()]],
        exit_signature_shards=[[faker.validator_signature()]],
        deadline=1000,
        amounts=[ether_to_gwei(32)],
        validators_manager_signature=faker.account_signature(),
    )
