import pytest

from src.config.settings import settings
from src.validators.keystores.hashi_vault import (
    HashiVaultConfiguration,
    HashiVaultKeystore,
)


class TestHashiVault:
    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_loading(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_path = 'ethereum/signing/keystores'

        config = HashiVaultConfiguration.from_settings()

        keystore = await HashiVaultKeystore._load_hashi_vault_keys(config)

        assert len(keystore) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_not_configured(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_token = None
        settings.hashi_vault_key_path = None

        with pytest.raises(RuntimeError, match='URL, token and key path must be specified'):
            await HashiVaultConfiguration.from_settings()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_inaccessible(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_path = 'ethereum/inaccessible/keystores'

        with pytest.raises(
            RuntimeError, match='Can not retrieve validator signing keys from hashi vault'
        ):
            config = HashiVaultConfiguration.from_settings()
            await HashiVaultKeystore._load_hashi_vault_keys(config)
