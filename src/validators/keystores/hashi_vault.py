import abc
import asyncio
import itertools
import logging
import urllib.parse
from dataclasses import dataclass
from typing import AsyncContextManager, Iterator

from aiohttp import ClientSession, ClientTimeout
from eth_typing import HexStr
from eth_utils import add_0x_prefix
from web3 import Web3

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

    def secret_url(self, key_path: str, location: str = 'data') -> str:
        return urllib.parse.urljoin(
            self.url,
            f'/v1/{self.engine_name}/{location}/{key_path}',
        )

    def prefix_url(self, keys_prefix: str) -> str:
        """An URL for Vault secrets engine location that holds prefixes for keys."""
        keys_prefix = keys_prefix.strip('/')
        # URL is used for listing, so it lists metadata
        return self.secret_url(keys_prefix, location='metadata')


@dataclass
class HashiVaultKeysLoader(metaclass=abc.ABCMeta):
    config: HashiVaultConfiguration
    input_iter: Iterator[str]

    def session(self) -> AsyncContextManager:
        return ClientSession(
            timeout=ClientTimeout(HASHI_VAULT_TIMEOUT),
            headers={'X-Vault-Token': self.config.token},
        )

    @staticmethod
    def merge_keys_responses(keys_responses: list[Keys], merged_keys: Keys) -> None:
        for keys in keys_responses:
            for pk, sk in keys.items():
                if pk in merged_keys:
                    logger.error('Duplicate validator key %s found in hashi vault', pk)
                    raise RuntimeError('Found duplicate key in path')
                merged_keys[pk] = sk

    async def load_into_merged(self, merged_keys: Keys) -> None:
        while key_chunk := list(itertools.islice(self.input_iter, self.config.parallelism)):
            await self.process_keys_chunk(key_chunk, merged_keys)

    @abc.abstractmethod
    async def process_keys_chunk(self, input_chunk: list[str], merged_keys: Keys) -> None:
        """Given input_iter list of keys, load either bundled or prefixed keys."""
        raise NotImplementedError


class HashiVaultBundledKeysLoader(HashiVaultKeysLoader):
    @staticmethod
    async def _load_bundled_hashi_vault_keys(session: ClientSession, secret_url: str) -> Keys:
        """
        Load public and private keys from hashi vault
        K/V secret engine.

        All public and private keys must be stored as hex string  with or without 0x prefix.
        """
        keys = []
        logger.info('Will load validator keys from %s', secret_url)

        response = await session.get(secret_url)
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

    async def process_keys_chunk(self, input_chunk: list[str], merged_keys: Keys) -> None:
        async with self.session() as session:
            keys_responses = await asyncio.gather(
                *[
                    self._load_bundled_hashi_vault_keys(
                        session=session,
                        secret_url=self.config.secret_url(key_path),
                    )
                    for key_path in input_chunk
                ]
            )
        self.merge_keys_responses(keys_responses, merged_keys)


@dataclass
class PrefixedKeysLoadedCallback:
    """Future done callback, that appends keys to shared dict."""

    prefix: str
    mapping: dict[str, list[str]]

    def __call__(self, keys_future_resolved: asyncio.Future) -> None:
        self.mapping.update({self.prefix: keys_future_resolved.result()})


class HashiVaultPrefixedKeysLoader(HashiVaultKeysLoader):
    @staticmethod
    async def _find_prefixed_hashi_vault_keys(session: ClientSession, prefix_url: str) -> list[str]:
        """
        Discover public keys under prefix in hashi vault K/V secret engine

        All public keys must be a final chunk of the secret path without 0x prefix,
        all secret keys are stored under these paths with arbitrary secret dictionary
        key, and secret value with or without 0x prefix.
        """
        logger.info('Will discover validator keys in %s', prefix_url)
        response = await session.request(method='LIST', url=prefix_url)
        response.raise_for_status()
        key_paths = await response.json()
        if 'data' not in key_paths:
            logger.error('Failed to discover keys in hashi vault')
            for error in key_paths.get('errors', []):
                logger.error('hashi vault error: %s', error)
            raise RuntimeError('Can not discover validator public keys from hashi vault')
        return key_paths['data']['keys']

    @staticmethod
    async def _load_prefixed_hashi_vault_key(session: ClientSession, secret_url: str) -> Keys:
        logger.info('Will load keys from %s', secret_url)
        response = await session.get(url=secret_url)
        response.raise_for_status()
        key_data = await response.json()
        if 'data' not in key_data:
            logger.error('Failed to retrieve keys from hashi vault')
            for error in key_data.get('errors', []):
                logger.error('hashi vault error: %s', error)
            raise RuntimeError('Can not retrieve validator signing keys from hashi vault')
        # Last chunk of URL is a public key
        pk = secret_url.strip('/').split('/')[-1].strip('0x')
        if len(key_data['data']['data']) > 1:
            raise RuntimeError(
                f'Invalid multi-value secret at path {secret_url}, '
                'should only contain single value',
            )
        sk = list(key_data['data']['data'].values())[0]
        sk_bytes = Web3.to_bytes(hexstr=sk)
        return Keys({add_0x_prefix(HexStr(pk)): BLSPrivkey(sk_bytes)})

    async def process_keys_chunk(self, input_chunk: list[str], merged_keys: Keys) -> None:
        prefixed_keys_mapping: dict[str, list[str]] = {}
        async with self.session() as session:
            futs = []
            for prefix_path in input_chunk:
                fut = asyncio.create_task(
                    self._find_prefixed_hashi_vault_keys(
                        session=session, prefix_url=self.config.prefix_url(prefix_path)
                    )
                )
                fut.add_done_callback(
                    PrefixedKeysLoadedCallback(
                        prefix=prefix_path,
                        mapping=prefixed_keys_mapping,
                    )
                )
                futs.append(fut)
            await asyncio.gather(*futs)

        # Flattened list of prefix, pubkey tuples
        keys_paired_with_prefix: list[tuple[str, str]] = sum(
            [
                [(prefix, pubkey) for pubkey in loaded_values]
                for (prefix, loaded_values) in prefixed_keys_mapping.items()
            ],
            [],
        )
        prefixed_keys_iter = iter(keys_paired_with_prefix)
        while prefixed_chunk := list(itertools.islice(prefixed_keys_iter, self.config.parallelism)):
            async with self.session() as session:
                keys_responses = await asyncio.gather(
                    *[
                        self._load_prefixed_hashi_vault_key(
                            session=session,
                            secret_url=self.config.secret_url(f'{key_prefix}/{key_path}'),
                        )
                        for (key_prefix, key_path) in prefixed_chunk
                    ]
                )
            self.merge_keys_responses(keys_responses, merged_keys)


class HashiVaultKeystore(LocalKeystore):
    @staticmethod
    async def load() -> 'HashiVaultKeystore':
        """Extracts private keys from the keystores."""
        hashi_vault_config = HashiVaultConfiguration.from_settings()

        merged_keys = Keys({})

        for loader_class, input_iter in {
            HashiVaultBundledKeysLoader: iter(hashi_vault_config.key_paths),
            HashiVaultPrefixedKeysLoader: iter(hashi_vault_config.key_prefixes),
        }.items():
            loader = loader_class(
                config=hashi_vault_config,
                input_iter=input_iter,
            )
            await loader.load_into_merged(merged_keys)

        return HashiVaultKeystore(merged_keys)
