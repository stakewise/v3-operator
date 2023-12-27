import logging

from src.config.settings import settings
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.hashi_vault import HashiVaultKeystore
from src.validators.keystores.local import LocalKeystore
from src.validators.keystores.remote import RemoteSignerKeystore

logger = logging.getLogger(__name__)


async def load_keystore() -> BaseKeystore:
    if settings.remote_signer_url:
        remote_keystore = await RemoteSignerKeystore.load()
        logger.info(
            'Using remote signer at %s for %i public keys',
            settings.remote_signer_url,
            len(remote_keystore),
        )
        return remote_keystore
    if settings.hashi_vault_url:
        logger.info('Using hashi vault at %s for loading public keys', settings.hashi_vault_url)
        return await HashiVaultKeystore.load()
    local_keystore = await LocalKeystore.load()
    if not local_keystore:
        raise RuntimeError('No keystore, no remote signer or hashi vault URL provided')
    return local_keystore
