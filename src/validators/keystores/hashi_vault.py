import asyncio
import itertools
import logging
import urllib.parse
from dataclasses import dataclass

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
    parallelism: int

    @classmethod
    def from_settings(cls) -> 'HashiVaultConfiguration':
        if not (
            settings.hashi_vault_url is not None
            and settings.hashi_vault_token is not None
            and settings.hashi_vault_key_paths is not None
        ):
            raise RuntimeError(
                'All three of URL, token and key path must be specified for hashi vault'
            )
        return cls(
            token=settings.hashi_vault_token,
            url=settings.hashi_vault_url,
            engine_name=settings.hashi_vault_engine_name,
            key_paths=settings.hashi_vault_key_paths,
            parallelism=settings.hashi_vault_parallelism,
        )

    def secret_url(self, key_path: str) -> str:
        return urllib.parse.urljoin(
            self.url,
            f'/v1/{self.engine_name}/data/{key_path}',
        )


class HashiVaultKeystore(LocalKeystore):
    @staticmethod
    async def load() -> 'HashiVaultKeystore':
        """Extracts private keys from the keystores."""
        hashi_vault_config = HashiVaultConfiguration.from_settings()

        parallelism = hashi_vault_config.parallelism
        key_paths = hashi_vault_config.key_paths
        merged_keys = Keys({})

        key_paths_iter = iter(key_paths)
        while key_chunk := list(itertools.islice(key_paths_iter, parallelism)):
            async with ClientSession(
                timeout=ClientTimeout(HASHI_VAULT_TIMEOUT),
                headers={'X-Vault-Token': hashi_vault_config.token},
            ) as session:
                keys_responses = await asyncio.gather(
                    *[
                        HashiVaultKeystore._load_hashi_vault_keys(
                            session=session,
                            secret_url=hashi_vault_config.secret_url(key_path),
                        )
                        for key_path in key_chunk
                    ]
                )
                for keys in keys_responses:
                    for pk, sk in keys.items():
                        if pk in merged_keys:
                            logger.error('Duplicate validator key %s found in hashi vault', pk)
                            raise RuntimeError('Found duplicate key in path')
                        merged_keys[pk] = sk
        return HashiVaultKeystore(merged_keys)

    @staticmethod
    async def _load_hashi_vault_keys(session: ClientSession, secret_url: str) -> Keys:
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
