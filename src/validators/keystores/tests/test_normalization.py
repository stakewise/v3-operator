import json

import pytest
from aioresponses import CallbackResult, aioresponses

from src.common.typings import normalize_public_key
from src.config.settings import settings
from src.validators.keystores.hashi_vault import HashiVaultKeystore
from src.validators.keystores.remote import RemoteSignerKeystore
from src.validators.keystores.tests.test_fixtures.hashi_vault import HashiVaultStub

PUBLIC_KEY = (
    '0xb79b844a8e2d2b9a1b3b0dbbedca4a1a1a8e8ed13e5cbb2d0b90bbb2d99b0be8'
    '00d2d3b4c1b6b3e0b1c2d3e4f5061728'
)


class TestNormalizePublicKey:
    @pytest.mark.parametrize(
        'public_key',
        [
            PUBLIC_KEY,
            PUBLIC_KEY.upper().replace('0X', '0x'),
            PUBLIC_KEY[2:],
            PUBLIC_KEY[2:].upper(),
        ],
    )
    def test_normalize_public_key(self, public_key):
        """Prefixed, unprefixed and upper case keys all collapse to the same form."""
        assert normalize_public_key(public_key) == PUBLIC_KEY


@pytest.mark.usefixtures('fake_settings')
class TestRemoteSignerNormalization:
    async def test_load_normalizes_public_keys(self, remote_signer_url):
        """Remote signer keys are normalized, so lookups by the canonical form match."""
        settings.remote_signer_url = remote_signer_url
        settings.remote_signer_public_keys_url = None

        # Web3Signer returns 0x-prefixed lower case keys, but that is not guaranteed
        # by the keymanager API.
        signer_public_keys = [PUBLIC_KEY[2:].upper(), PUBLIC_KEY.upper().replace('0X', '0x')]

        with aioresponses() as mocked:
            mocked.get(
                f'{remote_signer_url}/api/v1/eth2/publicKeys',
                callback=lambda url, **kwargs: CallbackResult(
                    status=200, body=json.dumps(signer_public_keys)
                ),
            )
            keystore = await RemoteSignerKeystore.load()

        assert keystore.public_keys == [PUBLIC_KEY, PUBLIC_KEY]
        assert PUBLIC_KEY in keystore


class TestHashiVaultNormalization:
    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_load_normalizes_public_keys(self, hashi_vault_url):
        """A key labeled in upper case without the 0x prefix is still found by its
        canonical form."""
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_engine_name = 'secret'
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_paths = ['ethereum/signing/uppercase/keystores']
        settings.hashi_vault_key_prefixes = []
        settings.hashi_vault_parallelism = 1

        keystore = await HashiVaultKeystore.load()

        assert keystore.public_keys == [HashiVaultStub.bundled_pk_1]
        assert HashiVaultStub.bundled_pk_1 in keystore
