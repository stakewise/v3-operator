import abc

from eth_typing import BLSSignature, HexStr
from sw_utils.typings import ConsensusFork


class BaseKeystore(abc.ABC):
    @staticmethod
    @abc.abstractmethod
    async def load() -> 'BaseKeystore':
        raise NotImplementedError

    @abc.abstractmethod
    def __bool__(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def __contains__(self, public_key: HexStr) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def __len__(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    async def get_exit_signature(
        self, validator_index: int, public_key: HexStr, fork: ConsensusFork
    ) -> BLSSignature:
        raise NotImplementedError

    @property
    @abc.abstractmethod
    def public_keys(self) -> list[HexStr]:
        raise NotImplementedError
