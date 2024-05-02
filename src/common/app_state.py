from dataclasses import dataclass

from eth_typing import BlockNumber

from src.common.typings import OraclesCache, Singleton


@dataclass
class ExitSignatureUpdateCache:
    checkpoint_block: BlockNumber | None = None
    last_event_block: BlockNumber | None = None


# pylint: disable-next=too-few-public-methods
class AppState(metaclass=Singleton):
    def __init__(self):
        self.exit_signature_update_cache = ExitSignatureUpdateCache()
        self.oracles_cache: OraclesCache | None = None
