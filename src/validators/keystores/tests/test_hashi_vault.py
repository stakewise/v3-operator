import pytest
from aiohttp.client import ClientSession

from src.config.settings import settings
from src.validators.keystores.hashi_vault import (
    HashiVaultBundledKeysLoader,
    HashiVaultConfiguration,
    HashiVaultKeystore,
    HashiVaultPrefixedKeysLoader,
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
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        config = HashiVaultConfiguration.from_settings()

        async with ClientSession() as session:
            keystore = await HashiVaultBundledKeysLoader._load_bundled_keys(
                session=session,
                secret_url=config.secret_url('ethereum/signing/keystores'),
            )

        assert len(keystore) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_prefixed_keystores_finding(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        config = HashiVaultConfiguration.from_settings()

        async with ClientSession() as session:
            keystores_prefixes = await HashiVaultPrefixedKeysLoader._find_prefixed_hashi_vault_keys(
                session=session,
                prefix='ethereum/signing/prefixed1',
                prefix_url=config.prefix_url('ethereum/signing/prefixed1'),
            )
        assert len(keystores_prefixes) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_prefixed_keystores_loading(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        config = HashiVaultConfiguration.from_settings()

        async with ClientSession() as session:
            keystore = await HashiVaultPrefixedKeysLoader._load_prefixed_key(
                session=session,
                secret_url=config.secret_url(
                    'ethereum/signing/prefixed1/8b09379ca969e8283a42a09285f430e8bd58c70bb33b44397ae81dac01b1403d0f631f156d211b6931a1c6284e2e469c',
                ),
            )
        assert list(keystore.keys()) == [
            '0x8b09379ca969e8283a42a09285f430e8bd58c70bb33b44397ae81dac01b1403d0f631f156d211b6931a1c6284e2e469c'
        ]

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
        settings.hashi_vault_key_path = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        with pytest.raises(
            RuntimeError, match='Can not retrieve validator signing keys from hashi vault'
        ):
            config = HashiVaultConfiguration.from_settings()
            async with ClientSession() as session:
                await HashiVaultBundledKeysLoader._load_bundled_keys(
                    session=session,
                    secret_url=config.secret_url('ethereum/inaccessible/keystores'),
                )

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

        config = HashiVaultConfiguration.from_settings()
        loader = HashiVaultBundledKeysLoader(
            config=config,
            input_iter=iter(settings.hashi_vault_key_paths),
        )
        keys = {}
        await loader.load(keys)

        assert len(keys) == 4

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

        config = HashiVaultConfiguration.from_settings()

        loader = HashiVaultBundledKeysLoader(
            config=config,
            input_iter=iter(settings.hashi_vault_key_paths),
        )
        keys = {}
        await loader.load(keys)

        assert len(keys) == 4

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

        keystore = HashiVaultKeystore({})
        with pytest.raises(RuntimeError, match='Found duplicate key in path'):
            await keystore.load()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_loading_custom_engine_name(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'custom'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_parallelism = 1

        config = HashiVaultConfiguration.from_settings()

        async with ClientSession() as session:
            keystore = await HashiVaultBundledKeysLoader._load_bundled_keys(
                session=session,
                secret_url=config.secret_url('ethereum/signing/keystores'),
            )

        assert len(keystore) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_prefixed_loader(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = []
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        config = HashiVaultConfiguration.from_settings()

        loader = HashiVaultPrefixedKeysLoader(
            config=config, input_iter=iter(['ethereum/signing/prefixed1'])
        )
        keystore = {}
        await loader.load(keystore)

        assert len(keystore) == 2

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

        keystore = HashiVaultKeystore({})
        keys = await keystore.load()
        assert len(keys) == 8
