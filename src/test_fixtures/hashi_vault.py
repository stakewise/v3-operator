import json
from functools import partial
from typing import Generator

import pytest
from aioresponses import CallbackResult, aioresponses
from sw_utils.tests import faker
from web3 import Web3


@pytest.fixture
def hashi_vault_url() -> str:
    return 'http://vault:8200'


class HashiVaultStub:
    bundled_pk_1 = faker.validator_public_key()
    bundled_sk_1 = Web3.to_hex(faker.private_key())

    bundled_pk_2 = faker.validator_public_key()
    bundled_sk_2 = Web3.to_hex(faker.private_key())

    bundled_pk_3 = faker.validator_public_key()
    bundled_sk_3 = Web3.to_hex(faker.private_key())

    bundled_pk_4 = faker.validator_public_key()
    bundled_sk_4 = Web3.to_hex(faker.private_key())

    prefixed_pk_1 = faker.validator_public_key()
    prefixed_sk_1 = Web3.to_hex(faker.private_key())

    prefixed_pk_2 = faker.validator_public_key()
    prefixed_sk_2 = Web3.to_hex(faker.private_key())

    prefixed_pk_3 = faker.validator_public_key()
    prefixed_sk_3 = Web3.to_hex(faker.private_key())

    prefixed_pk_4 = faker.validator_public_key()
    prefixed_sk_4 = Web3.to_hex(faker.private_key())


@pytest.fixture
def mocked_hashi_vault(
    hashi_vault_url: str,
) -> Generator:
    _hashi_vault_pk_sk_mapping_1 = {
        HashiVaultStub.bundled_pk_1: HashiVaultStub.bundled_sk_1,
        HashiVaultStub.bundled_pk_2: HashiVaultStub.bundled_sk_2,
    }
    _hashi_vault_pk_sk_mapping_2 = {
        HashiVaultStub.bundled_pk_3: HashiVaultStub.bundled_sk_3,
        HashiVaultStub.bundled_pk_4: HashiVaultStub.bundled_sk_4,
    }

    _hashi_vault_prefixed_pk_sk_mapping1 = {
        HashiVaultStub.prefixed_pk_1: HashiVaultStub.prefixed_sk_1,
        HashiVaultStub.prefixed_pk_2: HashiVaultStub.prefixed_sk_2,
    }

    _hashi_vault_prefixed_pk_sk_mapping2 = {
        HashiVaultStub.prefixed_pk_3: HashiVaultStub.prefixed_sk_3,
        HashiVaultStub.prefixed_pk_4: HashiVaultStub.prefixed_sk_4,
    }

    def _mocked_secret_path(data, url, **kwargs) -> CallbackResult:
        return CallbackResult(
            status=200,
            body=json.dumps(
                dict(
                    data=dict(
                        data=data,
                    )
                )
            ),  # type: ignore
        )

    def _mocked_secrets_list(data, url, **kwargs) -> CallbackResult:
        return CallbackResult(
            status=200,
            body=json.dumps(
                dict(
                    data=dict(
                        keys=data,
                    )
                )
            ),  # type: ignore
        )

    def _mocked_error_path(url, **kwargs) -> CallbackResult:
        return CallbackResult(
            status=200, body=json.dumps(dict(errors=list('token not provided')))  # type: ignore
        )

    with aioresponses() as m:
        # Mocked bundled signing keys endpoints
        m.get(
            f'{hashi_vault_url}/v1/secret/data/ethereum/signing/keystores',
            callback=partial(_mocked_secret_path, _hashi_vault_pk_sk_mapping_1),
            repeat=True,
        )
        m.get(
            f'{hashi_vault_url}/v1/secret/data/ethereum/signing/same/keystores',
            callback=partial(_mocked_secret_path, _hashi_vault_pk_sk_mapping_1),
            repeat=True,
        )
        m.get(
            f'{hashi_vault_url}/v1/secret/data/ethereum/signing/other/keystores',
            callback=partial(_mocked_secret_path, _hashi_vault_pk_sk_mapping_2),
            repeat=True,
        )
        # Mocked prefixed signing keys endpoints
        m.add(
            f'{hashi_vault_url}/v1/secret/metadata/ethereum/signing/prefixed1',
            callback=partial(
                _mocked_secrets_list, list(_hashi_vault_prefixed_pk_sk_mapping1.keys())
            ),
            repeat=True,
            method='LIST',
        )
        for _pk, _sk in _hashi_vault_prefixed_pk_sk_mapping1.items():
            m.get(
                f'{hashi_vault_url}/v1/secret/data/ethereum/signing/prefixed1/{_pk}',
                callback=partial(_mocked_secret_path, {'value': _sk}),
                repeat=True,
            )

        m.add(
            f'{hashi_vault_url}/v1/secret/metadata/ethereum/signing/prefixed2',
            callback=partial(
                _mocked_secrets_list, list(_hashi_vault_prefixed_pk_sk_mapping2.keys())
            ),
            repeat=True,
            method='LIST',
        )
        for _pk, _sk in _hashi_vault_prefixed_pk_sk_mapping2.items():
            m.get(
                f'{hashi_vault_url}/v1/secret/data/ethereum/signing/prefixed2/{_pk}',
                callback=partial(_mocked_secret_path, {'value': _sk}),
                repeat=True,
            )

        # Mocked bundled signing keys endpoints with custom engine name
        m.get(
            f'{hashi_vault_url}/v1/custom/data/ethereum/signing/keystores',
            callback=partial(_mocked_secret_path, _hashi_vault_pk_sk_mapping_1),
            repeat=True,
        )
        # Mocked inacessible signing keys endpoint
        m.get(
            f'{hashi_vault_url}/v1/secret/data/ethereum/inaccessible/keystores',
            callback=_mocked_error_path,
            repeat=True,
        )
        yield
