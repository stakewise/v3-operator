from dataclasses import dataclass
from typing import NewType

from eth_typing import BlockNumber, BLSSignature, ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils import ValidatorStatus
from web3.types import Gwei, Wei

from src.config.settings import MIN_ACTIVATION_BALANCE_GWEI, settings

BLSPrivkey = NewType('BLSPrivkey', bytes)


@dataclass
class NetworkValidator:
    public_key: HexStr
    block_number: BlockNumber


@dataclass
class VaultValidator:
    public_key: HexStr
    block_number: BlockNumber


@dataclass
class ExitSignatureShards:
    public_keys: list[HexStr]
    exit_signatures: list[HexStr]


@dataclass
class Validator:
    public_key: HexStr
    signature: HexStr
    amount: Gwei
    exit_signature: BLSSignature | None = None
    exit_signature_shards: ExitSignatureShards | None = None

    deposit_data_root: HexStr | None = None


@dataclass
class ConsensusValidator:
    index: int
    public_key: HexStr
    balance: Gwei
    withdrawal_credentials: HexStr
    status: ValidatorStatus
    activation_epoch: int

    @property
    def is_compounding(self) -> bool:
        return self.withdrawal_credentials.startswith('0x02')

    @property
    def withdrawal_capacity(self) -> Gwei:
        return Gwei(max(0, self.balance - MIN_ACTIVATION_BALANCE_GWEI))

    def is_partially_withdrawable(self, epoch: int) -> bool:
        return (
            self.is_compounding
            and self.status == ValidatorStatus.ACTIVE_ONGOING
            and self.activation_epoch < epoch - settings.network_config.SHARD_COMMITTEE_PERIOD
        )

    @staticmethod
    def from_consensus_data(beacon_validator: dict) -> 'ConsensusValidator':
        return ConsensusValidator(
            index=int(beacon_validator['index']),
            public_key=add_0x_prefix(beacon_validator['validator']['pubkey']),
            balance=Gwei(int(beacon_validator['balance'])),
            withdrawal_credentials=beacon_validator['validator']['withdrawal_credentials'],
            status=ValidatorStatus(beacon_validator['status']),
            activation_epoch=int(beacon_validator['validator']['activation_epoch']),
        )


@dataclass
class V2ValidatorEventData:
    public_key: HexStr
    amount: Wei


@dataclass
class RelayerValidatorsResponse:
    validators: list[Validator]
    validators_manager_signature: HexStr | None = None


@dataclass
class RelayerSignatureResponse:
    validators_manager_signature: HexStr


@dataclass
# pylint: disable-next=too-many-instance-attributes
class ApprovalRequest:
    validator_index: int
    vault_address: ChecksumAddress
    validators_root: HexStr
    public_keys: list[HexStr]
    deposit_signatures: list[HexStr]
    public_key_shards: list[list[HexStr]]
    exit_signature_shards: list[list[HexStr]]
    validators_manager_signature: HexStr
    deadline: int
    amounts: list[int] | None = None


@dataclass
class ConsolidationRequest:
    public_keys: list[HexStr]
    vault_address: ChecksumAddress


@dataclass
class ConsolidationKeys:
    source_public_keys: list[HexStr]
    target_public_key: HexStr

    @property
    def all_public_keys(self) -> list[HexStr]:
        return list(set(self.source_public_keys + [self.target_public_key]))
