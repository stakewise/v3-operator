import json
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
    #   --chain goerli \
    #   --num_validators 2 \
    #   --mnemonic 'provide iron update bronze session immense garage want round enhance artefact position make wash analyst skirt float jealous trend spread ginger rapid express tool'
    _hashi_vault_pk_sk_mapping = {
        'b05e93c4501233eeb7f1e7b0ee400caaa04608249c4aab61c18e04c675aaf2a0f03808d533c877fbbd57b04927c01ce0': '3eeedd7a6679d2e2036682b6f03ef16105a847321303aec163548aa3fa5e9eeb',
        'aa84894836cb3d897a1a11344920c41c472ed67667fd8a3453e557214442370ffc1d007ae7af67120de00afa068349be': '236f33410e6972a2db36ba3736099396768219b327e18eae49392f153007d468',
    }

    def _mocked_secret_path(url, **kwargs) -> CallbackResult:
        return CallbackResult(
            status=200,
            body=json.dumps(
                dict(
                    data=dict(
                        data=_hashi_vault_pk_sk_mapping,
                    )
                )
            ),  # type: ignore
        )

    def _mocked_error_path(url, **kwargs) -> CallbackResult:
        return CallbackResult(
            status=200, body=json.dumps(dict(errors=list('token not provided')))  # type: ignore
        )

    with aioresponses() as m:
        # Mocked signing keys endpoint
        m.get(
            f'{hashi_vault_url}/v1/secret/data/ethereum/signing/keystores',
            callback=_mocked_secret_path,
            repeat=True,
        )
        # Mocked inacessible signing keys endpoint
        m.get(
            f'{hashi_vault_url}/v1/secret/data/ethereum/inaccessible/keystores',
            callback=_mocked_error_path,
            repeat=True,
        )
        yield
