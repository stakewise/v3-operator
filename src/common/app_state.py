from dataclasses import dataclass

from eth_typing import BlockNumber, ChecksumAddress

from src.common.typings import Singleton
from src.config.settings import settings


@dataclass
class OraclesCache:
    checkpoint_block: BlockNumber
    config: dict
    validators_threshold: int
    rewards_threshold: int


@dataclass
class ExitSignatureUpdateCache:
    checkpoint_block: BlockNumber | None = None
    last_event_block: BlockNumber | None = None


class AppState(metaclass=Singleton):
    def __init__(self) -> None:
        self.exit_signature_update_cache: dict[ChecksumAddress, ExitSignatureUpdateCache] = {}
        self.partial_withdrawal_cache: dict[ChecksumAddress, BlockNumber | None] = {}
        self.reward_splitter_block: BlockNumber | None = None
        self.network_validators_block: BlockNumber | None = None
        for vault in settings.vaults:
            self.exit_signature_update_cache[vault] = ExitSignatureUpdateCache()
        self.oracles_cache: OraclesCache | None = None
