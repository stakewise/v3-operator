import pytest
from aioresponses import aioresponses
from eth_typing import ChecksumAddress, HexStr
from sw_utils.tests.factories import get_mocked_protocol_config
from sw_utils.typings import Oracle, ProtocolConfig
from web3 import Web3
from web3.types import Wei

from src.node_manager.oracles import poll_eligible_operators, send_registration_requests
from src.node_manager.typings import NodeManagerApprovalRequest

# --- poll_eligible_operators tests ---


@pytest.mark.usefixtures('fake_settings')
class TestPollEligibleOperators:
    @pytest.mark.asyncio
    async def test_returns_eligible_operators(self) -> None:
        config = _make_protocol_config([['http://oracle1']])
        response_data = [
            {'address': _make_address(10).lower(), 'amount': 32000000000000000000},
        ]

        with aioresponses() as m:
            m.get(
                'http://oracle1/nodes-manager/eligible-operators',
                payload=response_data,
            )
            result = await poll_eligible_operators(config)

        assert len(result) == 1
        assert result[0].address == _make_address(10)
        assert result[0].amount == Wei(32000000000000000000)

    @pytest.mark.asyncio
    async def test_returns_empty_on_all_failures(self) -> None:
        config = _make_protocol_config([['http://oracle1']])

        with aioresponses() as m:
            m.get(
                'http://oracle1/nodes-manager/eligible-operators',
                status=500,
            )
            result = await poll_eligible_operators(config)

        assert result == []

    @pytest.mark.asyncio
    async def test_falls_back_to_next_oracle(self) -> None:
        config = _make_protocol_config(
            [['http://oracle1'], ['http://oracle2']],
        )
        response_data = [
            {'address': _make_address(10).lower(), 'amount': 100},
        ]

        with aioresponses() as m:
            m.get('http://oracle1/nodes-manager/eligible-operators', status=500)
            m.get('http://oracle2/nodes-manager/eligible-operators', payload=response_data)
            result = await poll_eligible_operators(config)

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_replica_fallback(self) -> None:
        """If first replica fails, tries the next one."""
        config = _make_protocol_config([['http://replica1', 'http://replica2']])
        response_data = [{'address': _make_address(10).lower(), 'amount': 100}]

        with aioresponses() as m:
            m.get('http://replica1/nodes-manager/eligible-operators', status=500)
            m.get('http://replica2/nodes-manager/eligible-operators', payload=response_data)
            result = await poll_eligible_operators(config)

        assert len(result) == 1


# --- send_registration_requests tests ---


@pytest.mark.usefixtures('fake_settings')
class TestSendRegistrationRequests:
    @pytest.mark.asyncio
    async def test_collects_approvals(self) -> None:
        config = _make_protocol_config(
            [['http://oracle1'], ['http://oracle2']],
            threshold=2,
        )
        request = _make_registration_request()
        keeper_sig = '0x' + 'ab' * 65
        nm_sig = '0x' + 'cd' * 65

        oracle_response = {
            'keeperParams': {
                'signature': keeper_sig,
                'ipfs_hash': 'QmTestHash',
                'deadline': 1000,
            },
            'signature': nm_sig,
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

    @pytest.mark.asyncio
    async def test_partial_failure(self) -> None:
        """One oracle fails, the other succeeds — still returns what we got."""
        config = _make_protocol_config(
            [['http://oracle1'], ['http://oracle2']],
            threshold=1,
        )
        request = _make_registration_request()
        oracle_response = {
            'keeperParams': {
                'signature': '0x' + 'ab' * 65,
                'ipfs_hash': 'QmTestHash',
                'deadline': 1000,
            },
            'signature': '0x' + 'cd' * 65,
        }

        with aioresponses() as m:
            m.post('http://oracle1/nodes-manager/register-validators', status=500)
            m.post(
                'http://oracle2/nodes-manager/register-validators',
                payload=oracle_response,
            )
            approvals = await send_registration_requests(config, request)

        assert len(approvals) == 1


# --- Helpers ---

# Pre-generated distinct public keys (64 hex bytes each) so each Oracle gets a unique address.
_ORACLE_PUBKEYS: list[HexStr] = [HexStr(f'{i:02x}' * 64) for i in range(1, 10)]


def _make_address(i: int) -> ChecksumAddress:
    return Web3.to_checksum_address(f'0x{i:040x}')


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


def _make_registration_request() -> NodeManagerApprovalRequest:
    return NodeManagerApprovalRequest(
        validator_index=0,
        operator_address=_make_address(42),
        validators_root=HexStr('0x' + 'ab' * 32),
        public_keys=[HexStr('0x' + 'cc' * 48)],
        deposit_signatures=[HexStr('0x' + 'dd' * 96)],
        public_key_shards=[[HexStr('0xshard1')]],
        exit_signature_shards=[[HexStr('0xexitshard1')]],
        deadline=1000,
        amounts=[32000000000],
        signature=HexStr('0xsig'),
    )
