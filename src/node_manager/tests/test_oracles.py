import pytest
from eth_typing import ChecksumAddress
from web3 import Web3

from src.common.exceptions import (
    InvalidOraclesRequestError,
    NotEnoughOracleApprovalsError,
)
from src.node_manager.oracles import (
    _parse_registration_response,
    process_registration_approvals,
)
from src.node_manager.typings import (
    NodeManagerRegistrationApproval,
    NodeManagerRegistrationOraclesApproval,
)


class TestProcessRegistrationApprovals:
    def test_basic_consensus(self) -> None:
        """All oracles agree on the same ipfs_hash and deadline."""
        approvals = {
            _make_address(1): _make_registration_approval(
                keeper_sig=b'\x11' * 65, nm_sig=b'\x21' * 65
            ),
            _make_address(2): _make_registration_approval(
                keeper_sig=b'\x12' * 65, nm_sig=b'\x22' * 65
            ),
            _make_address(3): _make_registration_approval(
                keeper_sig=b'\x13' * 65, nm_sig=b'\x23' * 65
            ),
        }
        result = process_registration_approvals(approvals, votes_threshold=2)

        assert isinstance(result, NodeManagerRegistrationOraclesApproval)
        assert result.ipfs_hash == 'QmTest123'
        assert result.deadline == 1000
        # Signatures are sorted by oracle address (ascending int value) and truncated to threshold
        assert len(result.keeper_signatures) == 2 * 65
        assert len(result.nm_signatures) == 2 * 65

    def test_exact_threshold(self) -> None:
        """Exactly threshold votes should succeed."""
        approvals = {
            _make_address(1): _make_registration_approval(),
            _make_address(2): _make_registration_approval(),
        }
        result = process_registration_approvals(approvals, votes_threshold=2)
        assert len(result.keeper_signatures) == 2 * 65

    def test_below_threshold_raises(self) -> None:
        approvals = {
            _make_address(1): _make_registration_approval(),
        }
        with pytest.raises(NotEnoughOracleApprovalsError) as exc_info:
            process_registration_approvals(approvals, votes_threshold=2)
        assert exc_info.value.num_votes == 1
        assert exc_info.value.threshold == 2

    def test_empty_approvals_raises(self) -> None:
        with pytest.raises(InvalidOraclesRequestError):
            process_registration_approvals({}, votes_threshold=1)

    def test_split_vote_picks_majority(self) -> None:
        """When oracles disagree on ipfs_hash/deadline, pick the group with the most votes."""
        approvals = {
            _make_address(1): _make_registration_approval(ipfs_hash='QmA', deadline=100),
            _make_address(2): _make_registration_approval(ipfs_hash='QmB', deadline=200),
            _make_address(3): _make_registration_approval(ipfs_hash='QmA', deadline=100),
        }
        result = process_registration_approvals(approvals, votes_threshold=2)
        assert result.ipfs_hash == 'QmA'
        assert result.deadline == 100

    def test_split_vote_below_threshold(self) -> None:
        """No group reaches threshold → error."""
        approvals = {
            _make_address(1): _make_registration_approval(ipfs_hash='QmA', deadline=100),
            _make_address(2): _make_registration_approval(ipfs_hash='QmB', deadline=200),
            _make_address(3): _make_registration_approval(ipfs_hash='QmC', deadline=300),
        }
        with pytest.raises(NotEnoughOracleApprovalsError):
            process_registration_approvals(approvals, votes_threshold=2)

    def test_signatures_sorted_by_address(self) -> None:
        """Signatures are concatenated in ascending oracle address order."""
        addr_low = _make_address(1)
        addr_high = _make_address(0xFF)
        approvals = {
            addr_high: _make_registration_approval(keeper_sig=b'\xff' * 65, nm_sig=b'\xfe' * 65),
            addr_low: _make_registration_approval(keeper_sig=b'\x01' * 65, nm_sig=b'\x02' * 65),
        }
        result = process_registration_approvals(approvals, votes_threshold=2)
        # addr_low (0x01) sorts before addr_high (0xff)
        assert result.keeper_signatures[:65] == b'\x01' * 65
        assert result.keeper_signatures[65:] == b'\xff' * 65


class TestParsers:
    def test_parse_registration_response(self) -> None:
        keeper_sig_hex = '0x' + 'ab' * 65
        nm_sig_hex = '0x' + 'cd' * 65
        data = {
            'keeperParams': {
                'signature': keeper_sig_hex,
                'ipfs_hash': 'QmTest',
                'deadline': 12345,
            },
            'signature': nm_sig_hex,
        }
        result = _parse_registration_response(data)
        assert result.keeper_signature == Web3.to_bytes(hexstr=keeper_sig_hex)
        assert result.nm_signature == Web3.to_bytes(hexstr=nm_sig_hex)
        assert result.ipfs_hash == 'QmTest'
        assert result.deadline == 12345


# --- Helpers ---


def _make_address(i: int) -> ChecksumAddress:
    """Generate a deterministic checksum address from an integer."""
    return Web3.to_checksum_address(f'0x{i:040x}')


def _make_registration_approval(
    keeper_sig: bytes = b'\x01' * 65,
    nm_sig: bytes = b'\x02' * 65,
    ipfs_hash: str = 'QmTest123',
    deadline: int = 1000,
) -> NodeManagerRegistrationApproval:
    return NodeManagerRegistrationApproval(
        keeper_signature=keeper_sig,
        nm_signature=nm_sig,
        ipfs_hash=ipfs_hash,
        deadline=deadline,
    )
