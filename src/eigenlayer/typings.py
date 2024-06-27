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

    eigenpod: ChecksumAddress | None = None

    @property
    def withdrawal_address(self) -> ChecksumAddress:
        # withdrawal_credentials = ETH1_ADDRESS_WITHDRAWAL_PREFIX
        # withdrawal_credentials += b'\x00' * 11
        # withdrawal_credentials += to_canonical_address(vault)
        return Web3.to_checksum_address(self.withdrawal_credentials[26:])


@dataclass
class ValidatorInfo:
    validator_index: int
    # amount of beacon chain ETH restaked on EigenLayer in gwei
    restaked_balance_gwei: int
    # timestamp of the validator's most recent balance update
    most_recent_balance_update_timestamp: Timestamp
    # VALIDATOR_STATUS
    status: str


@dataclass
class VerifiedWithdrawal:
    amountToSendGwei: int
    restakedBalanceGwei: Wei  # gwei?


@dataclass
class DelayedWithdrawal:
    amount: int  # wei
    block_created: BlockNumber


@dataclass
class QueuedWithdrawal:
    staker: ChecksumAddress
    delegated_to: ChecksumAddress
    withdrawer: ChecksumAddress
    nonce: int
    start_block: BlockNumber
    strategies: list[ChecksumAddress]
    shares: list[Wei]  # gwei?

    withdrawal_root: bytes | None = None

    @property
    def block_number(self):
        return self.start_block
