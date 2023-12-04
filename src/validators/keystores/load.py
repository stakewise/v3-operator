import logging

from src.config.settings import settings
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.hashi_vault import HashiVaultKeystore
from src.validators.keystores.local import LocalKeystore
from src.validators.keystores.remote import RemoteSignerKeystore

logger = logging.getLogger(__name__)


async def load_keystores() -> BaseKeystore:
    if settings.remote_signer_url:
        # No keystores loaded but remote signer URL provided
        keystore = await RemoteSignerKeystore.load()
        logger.info(
            'Using remote signer at %s for %i public keys',
            settings.remote_signer_url,
            len(keystore),
        )
        return keystore
    if settings.hashi_vault_url:
        logger.info('Using hashi vault at %s for loading public keys')
        return await HashiVaultKeystore.load()
    keystores = await LocalKeystore.load()
    if not keystores:
        raise RuntimeError('No keystores, no remote signer or hashi vault URL provided')
    return keystores
