from dataclasses import dataclass

from eth_typing import BlockNumber

from src.common.base import Singleton


@dataclass
class ExitSignatureUpdateCache:
    checkpoint_block: BlockNumber | None = None
    last_event_block: BlockNumber | None = None


# pylint: disable-next=too-few-public-methods
class AppState(metaclass=Singleton):
    exit_signature_update_cache = ExitSignatureUpdateCache()
