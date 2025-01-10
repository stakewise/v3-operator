import pytest

from src.config.settings import settings
from src.test_fixtures.hashi_vault import HashiVaultStub
from src.validators.keystores.hashi_vault import (
    HashiVaultConfiguration,
    HashiVaultKeystore,
)


class TestHashiVault:
    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_bundled_keystores_loading(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = ['ethereum/signing/keystores']
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        keystore = await HashiVaultKeystore.load()

        assert len(keystore) == 2
        assert HashiVaultStub.bundled_pk_1 in keystore
        assert HashiVaultStub.bundled_pk_2 in keystore

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_not_configured(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = None
        settings.hashi_vault_key_path = None
        settings.hashi_vault_parallelism = 1

        with pytest.raises(RuntimeError, match='URL, token and key path must be specified'):
            await HashiVaultConfiguration.from_settings()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_bundled_keystores_inaccessible(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = ['ethereum/inaccessible/keystores']
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        with pytest.raises(
            RuntimeError, match='Can not retrieve validator signing keys from hashi vault'
        ):
            await HashiVaultKeystore.load()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_bundled_keystores_parallel(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/other/keystores',
        ]
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 2

        keystore = await HashiVaultKeystore.load()

        assert len(keystore) == 4
        assert HashiVaultStub.bundled_pk_1 in keystore
        assert HashiVaultStub.bundled_pk_2 in keystore
        assert HashiVaultStub.bundled_pk_3 in keystore
        assert HashiVaultStub.bundled_pk_4 in keystore

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_bundled_keystores_sequential(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/other/keystores',
        ]
        settings.hashi_vault_parallelism = 1

        keystore = await HashiVaultKeystore.load()

        assert len(keystore) == 4
        assert HashiVaultStub.bundled_pk_1 in keystore
        assert HashiVaultStub.bundled_pk_2 in keystore
        assert HashiVaultStub.bundled_pk_3 in keystore
        assert HashiVaultStub.bundled_pk_4 in keystore

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_duplicates_parallel(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/same/keystores',
        ]
        settings.hashi_vault_parallelism = 2

        with pytest.raises(RuntimeError, match='Duplicate validator key'):
            await HashiVaultKeystore.load()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_loading_custom_engine_name(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'custom'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = ['ethereum/signing/keystores']
        settings.hashi_vault_parallelism = 1

        keystore = await HashiVaultKeystore.load()

        assert len(keystore) == 2
        assert HashiVaultStub.bundled_pk_1 in keystore
        assert HashiVaultStub.bundled_pk_2 in keystore

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_prefixed_loader(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = ['ethereum/signing/prefixed1']
        settings.hashi_vault_parallelism = 1

        keystore = await HashiVaultKeystore.load()

        assert len(keystore) == 2
        assert HashiVaultStub.prefixed_pk_1 in keystore
        assert HashiVaultStub.prefixed_pk_2 in keystore

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_load_bundled_and_prefixed(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = [
            'ethereum/signing/keystores',
            'ethereum/signing/other/keystores',
        ]
        settings.hashi_vault_key_prefixes = [
            'ethereum/signing/prefixed1',
            'ethereum/signing/prefixed2',
        ]
        settings.hashi_vault_parallelism = 2

        keystore = await HashiVaultKeystore.load()

        assert len(keystore) == 8

        assert HashiVaultStub.bundled_pk_1 in keystore
        assert HashiVaultStub.bundled_pk_2 in keystore
        assert HashiVaultStub.bundled_pk_3 in keystore
        assert HashiVaultStub.bundled_pk_4 in keystore

        assert HashiVaultStub.prefixed_pk_1 in keystore
        assert HashiVaultStub.prefixed_pk_2 in keystore
        assert HashiVaultStub.prefixed_pk_3 in keystore
        assert HashiVaultStub.prefixed_pk_4 in keystore
