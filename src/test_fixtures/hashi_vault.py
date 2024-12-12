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

    # Generated via
    # eth-staking-smith existing-mnemonic \
    #   --chain holesky \
    #   --num_validators 2 \
    #   --mnemonic 'route flight verb churn work creek crane hole obscure young shaft area bird border refuse usage flash engage burden retreat drama bamboo profit sense'
    _hashi_vault_prefixed_pk_sk_mapping1 = {
        '8b09379ca969e8283a42a09285f430e8bd58c70bb33b44397ae81dac01b1403d0f631f156d211b6931a1c6284e2e469c': '5d88e114821bf871f321399d99fe58cb24d6434b416f112e8e46077e05399dc0',
        '8979806d4e5d841758868b208df0dd961c12a0cf044e2de1d18e269ca0ad0308672be2f71d3d5606834764fe5b1d0bc4': '01352aec5cadb78eba6f716570d28b40f24b96c522dac535bc81375ceb54bf0b',
    }

    # Generated via
    # eth-staking-smith existing-mnemonic \
    #   --chain holesky \
    #   --num_validators 2 \
    #   --mnemonic 'lion toilet tooth guess excuse wise amateur evolve moment damage curtain image zebra dress drill circle luggage seminar similar symptom happy floor govern gravity'
    _hashi_vault_prefixed_pk_sk_mapping2 = {
        '859f3fc64e32a1e95aadc7a7ec35207f6305951e7dafacf9252aaa9edef3d1edf74d268041cb59ca64e703ba064890be': '17dd0ad25bd239092bfa47b53c94d7eec2f3621a99ffafc28cd3c6b25a72d7f9',
        'a60dcf78a344afc297b4917f76b5b387924153182390361d5199c3455299d67fbb932b77943ffe5477150304f3cb600f': '4f768f0b9589fdff6e8371dd268d8d78b97bf968f6fc469657332cff48b1dea4',
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
