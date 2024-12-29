import abc
import asyncio
import logging
import urllib.parse
from dataclasses import dataclass
from typing import Iterable

from aiohttp import ClientSession, ClientTimeout
from eth_typing import HexStr
from eth_utils import add_0x_prefix
from web3 import Web3

from src.common.utils import chunkify
from src.config.settings import HASHI_VAULT_TIMEOUT, settings
from src.validators.keystores.local import Keys, LocalKeystore
from src.validators.typings import BLSPrivkey

logger = logging.getLogger(__name__)


@dataclass
class HashiVaultConfiguration:
    token: str
    url: str
    engine_name: str
    key_paths: list[str]
    key_prefixes: list[str]
    parallelism: int

    @classmethod
    def from_settings(cls) -> 'HashiVaultConfiguration':
        if not (
            settings.hashi_vault_url is not None
            and settings.hashi_vault_token is not None
            and (
                settings.hashi_vault_key_paths is not None
                or settings.hashi_vault_key_prefixes is not None
            )
        ):
            raise RuntimeError(
                'All three of URL, token and key path must be specified for hashi vault'
            )
        return cls(
            token=settings.hashi_vault_token,
            url=settings.hashi_vault_url,
            engine_name=settings.hashi_vault_engine_name,
            key_paths=settings.hashi_vault_key_paths or [],
            key_prefixes=settings.hashi_vault_key_prefixes or [],
            parallelism=settings.hashi_vault_parallelism,
        )

    def prefix_url(self, keys_prefix: str) -> str:
        """An URL for Vault secrets engine location that holds prefixes for keys."""
        keys_prefix = keys_prefix.strip('/')
        # URL is used for listing, so it lists metadata
        return self.secret_url(keys_prefix, location='metadata')

    def secret_url(self, key_path: str, location: str = 'data') -> str:
        return urllib.parse.urljoin(
            self.url,
            f'/v1/{self.engine_name}/{location}/{key_path}',
        )


class HashiKeys:
    """
    Wrapper around Keys that proactively searches for duplicate keys to prevent
    potential slashing.
    """

    def __init__(self, keys: Keys | None = None):
        self.keys = keys or Keys({})

    def __getitem__(self, key: HexStr) -> BLSPrivkey:
        return self.keys[key]

    def __setitem__(self, key: HexStr, value: BLSPrivkey) -> None:
        if key in self.keys:
            raise RuntimeError(f'Duplicate validator key {key} found in hashi vault')
        self.keys[key] = value

    def items(self) -> Iterable[tuple[HexStr, BLSPrivkey]]:
        return self.keys.items()

    def update(self, new_keys: 'HashiKeys' | Keys) -> None:
        for key, value in new_keys.items():
            self[key] = value

    def __len__(self) -> int:
        return len(self.keys)

    def __repr__(self) -> str:
        return f'HashiKeys({self.keys})'


@dataclass
class HashiVaultKeysLoader(metaclass=abc.ABCMeta):
    config: HashiVaultConfiguration

    def session(self) -> ClientSession:
        return ClientSession(
            timeout=ClientTimeout(HASHI_VAULT_TIMEOUT),
            headers={'X-Vault-Token': self.config.token},
        )

    @abc.abstractmethod
    async def load(self) -> HashiKeys:
        """Load validator keys"""
        raise NotImplementedError


class HashiVaultBundledKeysLoader(HashiVaultKeysLoader):
    async def load(self) -> HashiKeys:
        async with self.session() as session:
            return await self._load_from_key_paths(session=session)

    async def _load_from_key_paths(self, session: ClientSession) -> HashiKeys:
        """Load all the key bundles from key paths."""
        merged_keys = HashiKeys()

        for key_chunk in chunkify(self.config.key_paths, self.config.parallelism):
            keys_responses = await asyncio.gather(
                *[
                    self._load_bundled_keys(session=session, key_path=key_path)
                    for key_path in key_chunk
                ]
            )
            for keys_response in keys_responses:
                merged_keys.update(keys_response)

        return merged_keys

    async def _load_bundled_keys(self, session: ClientSession, key_path: str) -> Keys:
        """
        Load public and private keys from hashi vault
        K/V secret engine.

        All public and private keys must be stored as hex string  with or without 0x prefix.
        """
        keys = []
        secret_url = self.config.secret_url(key_path)
        logger.info('Will load validator keys from %s', secret_url)

        async with session.get(secret_url) as response:
            response.raise_for_status()
            key_data = await response.json()

        if 'data' not in key_data:
            logger.error('Failed to retrieve keys from hashi vault')
            for error in key_data.get('errors', []):
                logger.error('hashi vault error: %s', error)
            raise RuntimeError('Can not retrieve validator signing keys from hashi vault')

        for pk, sk in key_data['data']['data'].items():
            sk_bytes = Web3.to_bytes(hexstr=sk)
            keys.append((add_0x_prefix(HexStr(pk)), BLSPrivkey(sk_bytes)))
        validator_keys = Keys(dict(keys))
        return validator_keys


class HashiVaultPrefixedKeysLoader(HashiVaultKeysLoader):
    async def load(self) -> HashiKeys:
        async with self.session() as session:
            return await self._load_from_key_prefixes(session=session)

    async def _load_from_key_prefixes(self, session: ClientSession) -> HashiKeys:
        """Discover all the keys under given prefix. Then, load the keys into merged structure."""
        merged_keys = HashiKeys()
        prefix_pubkey_pairs = await self._get_prefix_pubkey_pairs(session=session)

        for prefix_pubkey_chunk in chunkify(prefix_pubkey_pairs, self.config.parallelism):
            keys_responses = await asyncio.gather(
                *[
                    self._load_prefixed_key(session=session, prefix=prefix, pubkey=pubkey)
                    for prefix, pubkey in prefix_pubkey_chunk
                ]
            )
            for keys_response in keys_responses:
                merged_keys.update(keys_response)

        return merged_keys

    async def _get_prefix_pubkey_pairs(self, session: ClientSession) -> list[tuple[str, str]]:
        prefix_pubkey_pairs: list[tuple[str, str]] = []

        for prefix_chunk in chunkify(self.config.key_prefixes, self.config.parallelism):
            keys_results = await asyncio.gather(
                *[
                    self._find_keys_by_prefix(
                        session=session,
                        prefix=prefix_path,
                    )
                    for prefix_path in prefix_chunk
                ]
            )
            for prefix, keys in zip(prefix_chunk, keys_results):
                for key in keys:
                    prefix_pubkey_pairs.append((prefix, key))

        return prefix_pubkey_pairs

    async def _find_keys_by_prefix(self, session: ClientSession, prefix: str) -> list[str]:
        """
        Discover public keys under prefix in hashi vault K/V secret engine

        All public keys must be a final chunk of the secret path without 0x prefix,
        all secret keys are stored under these paths with arbitrary secret dictionary
        key, and secret value with or without 0x prefix.

        """
        prefix_url = self.config.prefix_url(prefix)
        logger.info('Will discover validator keys in %s', prefix_url)

        async with session.request(method='LIST', url=prefix_url) as response:
            response.raise_for_status()
            key_paths = await response.json()

        if 'data' not in key_paths:
            logger.error('Failed to discover keys in hashi vault')
            for error in key_paths.get('errors', []):
                logger.error('hashi vault error: %s', error)
            raise RuntimeError('Can not discover validator public keys from hashi vault')
        discovered_keys = key_paths['data']['keys']
        return discovered_keys

    async def _load_prefixed_key(self, session: ClientSession, prefix: str, pubkey: str) -> Keys:
        secret_url = self.config.secret_url(f'{prefix}/{pubkey}')
        logger.info('Will load keys from %s', secret_url)

        async with session.get(url=secret_url) as response:
            response.raise_for_status()
            key_data = await response.json()

        if 'data' not in key_data:
            logger.error('Failed to retrieve keys from hashi vault')
            for error in key_data.get('errors', []):
                logger.error('hashi vault error: %s', error)
            raise RuntimeError('Can not retrieve validator signing keys from hashi vault')
        # Last chunk of URL is a public key
        pk = add_0x_prefix(HexStr(secret_url.strip('/').split('/')[-1]))
        if len(key_data['data']['data']) > 1:
            raise RuntimeError(
                f'Invalid multi-value secret at path {secret_url}, '
                'should only contain single value',
            )
        sk = list(key_data['data']['data'].values())[0]
        sk_bytes = Web3.to_bytes(hexstr=sk)
        return Keys({pk: BLSPrivkey(sk_bytes)})


class HashiVaultKeystore(LocalKeystore):
    def __init__(self, keys: HashiKeys):
        super().__init__(keys.keys)

    @staticmethod
    async def load() -> 'HashiVaultKeystore':
        """Extracts private keys from the keystores."""
        hashi_vault_config = HashiVaultConfiguration.from_settings()  # noqa: NEW100

        merged_keys = HashiKeys()

        for loader_class in [HashiVaultBundledKeysLoader, HashiVaultPrefixedKeysLoader]:
            loader = loader_class(config=hashi_vault_config)
            keys = await loader.load()
            merged_keys.update(keys)

        return HashiVaultKeystore(merged_keys)
