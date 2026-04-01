import pytest
from eth_typing import ChecksumAddress, HexStr
from sw_utils.tests.factories import faker

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

ORACLE_ADDRESSES: list[ChecksumAddress] = sorted(
    [faker.eth_address() for _ in range(5)],
)


class TestProcessRegistrationApprovals:
    def test_basic_consensus(self) -> None:
        """All oracles agree on the same ipfs_hash and deadline."""
        approvals = {
            ORACLE_ADDRESSES[0]: _make_registration_approval(
                keeper_sig=HexStr(faker.account_signature()),
                sig=HexStr(faker.account_signature()),
            ),
            ORACLE_ADDRESSES[1]: _make_registration_approval(
                keeper_sig=HexStr(faker.account_signature()),
                sig=HexStr(faker.account_signature()),
            ),
            ORACLE_ADDRESSES[2]: _make_registration_approval(
                keeper_sig=HexStr(faker.account_signature()),
                sig=HexStr(faker.account_signature()),
            ),
        }
        result = process_registration_approvals(approvals, votes_threshold=2)

        assert isinstance(result, NodeManagerRegistrationOraclesApproval)
        assert result.ipfs_hash == 'QmTest123'
        assert result.deadline == 1000
        # Signatures are sorted by oracle address (ascending int value) and truncated to threshold
        assert len(result.keeper_signatures) == 2
        assert len(result.signatures) == 2

    def test_exact_threshold(self) -> None:
        """Exactly threshold votes should succeed."""
        approvals = {
            ORACLE_ADDRESSES[0]: _make_registration_approval(),
            ORACLE_ADDRESSES[1]: _make_registration_approval(),
        }
        result = process_registration_approvals(approvals, votes_threshold=2)
        assert len(result.keeper_signatures) == 2

    def test_below_threshold_raises(self) -> None:
        approvals = {
            ORACLE_ADDRESSES[0]: _make_registration_approval(),
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
            ORACLE_ADDRESSES[0]: _make_registration_approval(ipfs_hash='QmA', deadline=100),
            ORACLE_ADDRESSES[1]: _make_registration_approval(ipfs_hash='QmB', deadline=200),
            ORACLE_ADDRESSES[2]: _make_registration_approval(ipfs_hash='QmA', deadline=100),
        }
        result = process_registration_approvals(approvals, votes_threshold=2)
        assert result.ipfs_hash == 'QmA'
        assert result.deadline == 100

    def test_split_vote_below_threshold(self) -> None:
        """No group reaches threshold → error."""
        approvals = {
            ORACLE_ADDRESSES[0]: _make_registration_approval(ipfs_hash='QmA', deadline=100),
            ORACLE_ADDRESSES[1]: _make_registration_approval(ipfs_hash='QmB', deadline=200),
            ORACLE_ADDRESSES[2]: _make_registration_approval(ipfs_hash='QmC', deadline=300),
        }
        with pytest.raises(NotEnoughOracleApprovalsError):
            process_registration_approvals(approvals, votes_threshold=2)

    def test_signatures_sorted_by_address(self) -> None:
        """Signatures are concatenated in ascending oracle address order."""
        addr_low = ORACLE_ADDRESSES[0]
        addr_high = ORACLE_ADDRESSES[-1]
        keeper_sig_low = HexStr(faker.account_signature())
        keeper_sig_high = HexStr(faker.account_signature())
        sig_low = HexStr(faker.account_signature())
        sig_high = HexStr(faker.account_signature())
        approvals = {
            addr_high: _make_registration_approval(keeper_sig=keeper_sig_high, sig=sig_high),
            addr_low: _make_registration_approval(keeper_sig=keeper_sig_low, sig=sig_low),
        }
        result = process_registration_approvals(approvals, votes_threshold=2)
        assert result.keeper_signatures[0] == keeper_sig_low
        assert result.keeper_signatures[1] == keeper_sig_high


class TestParsers:
    def test_parse_registration_response(self) -> None:
        keeper_sig_hex = faker.account_signature()
        sig_hex = faker.account_signature()
        data = {
            'keeperParams': {
                'signature': keeper_sig_hex,
                'ipfs_hash': 'QmTest',
                'deadline': 12345,
            },
            'signature': sig_hex,
        }
        result = _parse_registration_response(data)
        assert result.keeper_signature == keeper_sig_hex
        assert result.nodes_manager_signature == sig_hex
        assert result.ipfs_hash == 'QmTest'
        assert result.deadline == 12345


# --- Helpers ---


def _make_registration_approval(
    keeper_sig: HexStr | None = None,
    sig: HexStr | None = None,
    ipfs_hash: str = 'QmTest123',
    deadline: int = 1000,
) -> NodeManagerRegistrationApproval:
    if keeper_sig is None:
        keeper_sig = HexStr(faker.account_signature())
    if sig is None:
        sig = HexStr(faker.account_signature())
    return NodeManagerRegistrationApproval(
        keeper_signature=keeper_sig,
        nodes_manager_signature=sig,
        ipfs_hash=ipfs_hash,
        deadline=deadline,
    )
