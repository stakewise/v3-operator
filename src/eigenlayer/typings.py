from dataclasses import dataclass

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from sw_utils.consensus import ValidatorStatus
from web3 import Web3
from web3.types import Timestamp, Wei


@dataclass
class Withdrawal:
    block_number: BlockNumber
    validator_index: int
    amount: int  # gwei
    index: int
    withdrawal_address: ChecksumAddress
    slot: int | None = None


@dataclass
class Validator:
    public_key: HexStr
    index: int
    status: ValidatorStatus
    withdrawal_credentials: HexStr
    activation_epoch: int

    @property
    def withdrawal_address(self) -> ChecksumAddress:
        # address is a first 26 bytes of withdrawal_credentials
        withdrawal_address_byte_length = 26

        return Web3.to_checksum_address(
            self.withdrawal_credentials[withdrawal_address_byte_length:]
        )


@dataclass
class ValidatorInfo:
    validator_index: int
    restaked_balance_gwei: int
    most_recent_balance_update_timestamp: Timestamp
    status: str


@dataclass
# pylint: disable-next=too-many-instance-attributes
class QueuedWithdrawal:
    staker: ChecksumAddress
    delegated_to: ChecksumAddress
    withdrawer: ChecksumAddress
    nonce: int
    start_block: BlockNumber
    strategies: list[ChecksumAddress]
    shares: list[Wei]

    undelegation: bool = False
    withdrawal_root: bytes | None = None

    @property
    def block_number(self):
        return self.start_block

    @property
    def total_shares(self) -> Wei:
        return Wei(sum(self.shares))
