import json
from functools import partial
from typing import Generator

import pytest
from aioresponses import CallbackResult, aioresponses


@pytest.fixture
def hashi_vault_url() -> str:
    return 'http://vault:8200'


@pytest.fixture
def mocked_hashi_vault(
    hashi_vault_url: str,
) -> Generator:
    # Generated via
    # eth-staking-smith existing-mnemonic \
    #   --chain holesky \
    #   --num_validators 2 \
    #   --mnemonic 'provide iron update bronze session immense garage want round enhance artefact position make wash analyst skirt float jealous trend spread ginger rapid express tool'
    _hashi_vault_pk_sk_mapping_1 = {
        'b05e93c4501233eeb7f1e7b0ee400caaa04608249c4aab61c18e04c675aaf2a0f03808d533c877fbbd57b04927c01ce0': '3eeedd7a6679d2e2036682b6f03ef16105a847321303aec163548aa3fa5e9eeb',
        'aa84894836cb3d897a1a11344920c41c472ed67667fd8a3453e557214442370ffc1d007ae7af67120de00afa068349be': '236f33410e6972a2db36ba3736099396768219b327e18eae49392f153007d468',
    }
    # Generated via
    # eth-staking-smith existing-mnemonic \
    #   --chain holesky \
    #   --num_validators 2 \
    #   --mnemonic 'wheel treat brand feel motion atom card impose achieve rough shove bless glory wheel gold ensure maid despair turtle carry recall best outer fuel'
    _hashi_vault_pk_sk_mapping_2 = {
        '9548e46c8e3b11d686b11fe5c4aea53a6ffd6cef622920fe8d73b4b7bff71938d2a0652b607fa6d757e840f3ddc2d7a4': '2c7310981a6e12bef7f444860b450c70235acd3e9f74e0a3ee82da3fdbc657a5',
        '8bc90a3110cf2b1ebaf8f5367bbfec1066797fca1f71ddbbf4f8f37ef74064404a78c31284c571656b7cb6efa29445ab': '56336628453e51cb9158da0651ea27dcb297eacdbd5cffdf0ea9d65fa154c327',
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

    def _mocked_error_path(url, **kwargs) -> CallbackResult:
        return CallbackResult(
            status=200, body=json.dumps(dict(errors=list('token not provided')))  # type: ignore
        )

    with aioresponses() as m:
        # Mocked signing keys endpoints
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
        # Mocked signing keys endpoints with custom engine name
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
