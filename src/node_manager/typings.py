from dataclasses import dataclass

from eth_typing import ChecksumAddress, HexStr
from web3.types import Wei


@dataclass
class EligibleOperator:
    """Operator eligible to register or fund validators."""

    address: ChecksumAddress
    amount: Wei


@dataclass
# pylint: disable-next=too-many-instance-attributes
class NodeManagerApprovalRequest:
    """Approval request for NodesManager validator registration."""

    validator_index: int
    operator_address: ChecksumAddress
    validators_root: HexStr
    public_keys: list[HexStr]
    deposit_signatures: list[HexStr]
    public_key_shards: list[list[HexStr]]
    exit_signature_shards: list[list[HexStr]]
    deadline: int
    amounts: list[int]
    signature: HexStr


@dataclass
class NodeManagerRegistrationApproval:
    """Single oracle's registration response with both signature types."""

    signature: HexStr
    keeper_signature: HexStr
    ipfs_hash: str
    deadline: int


@dataclass
class NodeManagerRegistrationOraclesApproval:
    """Combined registration approval from multiple oracles."""

    signatures: HexStr
    keeper_signatures: HexStr
    ipfs_hash: str
    deadline: int
