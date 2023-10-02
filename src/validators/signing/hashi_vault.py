import logging
import urllib.parse
from dataclasses import dataclass

from aiohttp import ClientSession, ClientTimeout
from eth_typing import HexStr
from eth_utils import add_0x_prefix
from web3 import Web3

from src.config.settings import HASHI_VAULT_TIMEOUT, settings
from src.validators.typings import BLSPrivkey, Keystores

logger = logging.getLogger(__name__)


@dataclass
class HashiVaultConfiguration:
    token: str
    url: str
    key_path: str

    @classmethod
    def from_settings(cls):
        if not (
            settings.hashi_vault_url is not None
            and settings.hashi_vault_token is not None
            and settings.hashi_vault_key_path is not None
        ):
            raise RuntimeError(
                'All three of URL, token and key path must be specified for hashi vault'
            )
        return cls(
            token=settings.hashi_vault_token,
            url=settings.hashi_vault_url,
            key_path=settings.hashi_vault_key_path,
        )

    def secret_url(self):
        return urllib.parse.urljoin(
            self.url,
            f'/v1/secret/data/{self.key_path}',
        )


async def load_hashi_vault_keys(config: HashiVaultConfiguration) -> Keystores:
    """
    Load public and private keys from hashi vault
    K/V secret engine.

    All public and private keys must be stored as hex string  with or without 0x prefix.
    """
    keys = []
    logger.info('Will load validator keys from %s', config.secret_url())

    async with ClientSession(timeout=ClientTimeout(HASHI_VAULT_TIMEOUT)) as session:
        response = await session.get(config.secret_url(), headers={'X-Vault-Token': config.token})
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
    validator_keys = Keystores(dict(keys))
    return validator_keys
