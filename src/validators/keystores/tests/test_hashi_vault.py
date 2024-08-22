import pytest
from aiohttp.client import ClientSession

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
        settings.hashi_vault_engine_name = "secret"
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_parallelism = 1

        config = HashiVaultConfiguration.from_settings()

        async with ClientSession() as session:
            keystore = await HashiVaultKeystore._load_hashi_vault_keys(
                session=session, secret_url=config.secret_url('secret', 'ethereum/signing/keystores')
            )

        assert len(keystore) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_not_configured(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = "secret"
        settings.hashi_vault_token = None
        settings.hashi_vault_key_path = None
        settings.hashi_vault_parallelism = 1

        with pytest.raises(RuntimeError, match='URL, token and key path must be specified'):
            await HashiVaultConfiguration.from_settings()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_inaccessible(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = "secret"
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_path = []
        settings.hashi_vault_parallelism = 1

        with pytest.raises(
            RuntimeError, match='Can not retrieve validator signing keys from hashi vault'
        ):
            config = HashiVaultConfiguration.from_settings()
            async with ClientSession() as session:
                await HashiVaultKeystore._load_hashi_vault_keys(
                    session=session, secret_url=config.secret_url('secret', 'ethereum/inaccessible/keystores')
                )

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_parallel(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = "secret"
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/other/keystores',
        ]
        settings.hashi_vault_parallelism = 2

        keystore = HashiVaultKeystore({})
        keys = await keystore.load()

        assert len(keys) == 4

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_sequential(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = "secret"
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/other/keystores',
        ]
        settings.hashi_vault_parallelism = 1

        keystore = HashiVaultKeystore({})
        keys = await keystore.load()

        assert len(keys) == 4

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_duplicates_parallel(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = "secret"
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/same/keystores',
        ]
        settings.hashi_vault_parallelism = 2

        keystore = HashiVaultKeystore({})
        with pytest.raises(RuntimeError, match='Found duplicate key in path'):
            await keystore.load()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_loading_custom_engine_name(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = "custom"
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_parallelism = 1

        config = HashiVaultConfiguration.from_settings()

        async with ClientSession() as session:
            keystore = await HashiVaultKeystore._load_hashi_vault_keys(
                session=session, secret_url=config.secret_url('custom', 'ethereum/signing/keystores')
            )

        assert len(keystore) == 2
