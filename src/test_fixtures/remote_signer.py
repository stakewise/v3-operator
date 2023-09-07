# pylint: disable=redefined-outer-name
import json
import re
from typing import Generator

import milagro_bls_binding as bls
import pytest
from aioresponses import CallbackResult, aioresponses
from eth_typing import HexStr
from staking_deposit.key_handling.keystore import Keystore
from web3 import Web3

from src.validators.typings import BLSPrivkey


@pytest.fixture
def remote_signer_url() -> str:
    return 'http://web3signer:9000'


@pytest.fixture
def mocked_remote_signer(
    remote_signer_url: str,
) -> Generator:
    _remote_signer_pubkey_privkey_mapping: dict[HexStr, BLSPrivkey] = {}

    # pylint: disable-next=unused-argument
    def _mocked_import_endpoint(url, **kwargs) -> CallbackResult:
        data = kwargs['json']
        keystores = [Keystore.from_json(json.loads(keystore)) for keystore in data['keystores']]
        passwords = data['passwords']

        for keystore, password in zip(keystores, passwords):
            priv_key = BLSPrivkey(keystore.decrypt(password))
            pubkey = Web3.to_hex(bls.SkToPk(priv_key))
            _remote_signer_pubkey_privkey_mapping[pubkey] = priv_key

        return CallbackResult(
            status=200, payload={'data': [{'status': 'imported'} for _ in keystores]}
        )

    # pylint: disable-next=unused-argument
    def _mocked_delete_endpoint(url, **kwargs) -> CallbackResult:
        data = kwargs['json']
        pubkeys = data['pubkeys']

        for pubkey in pubkeys:
            _remote_signer_pubkey_privkey_mapping.pop(pubkey)

        return CallbackResult(
            status=200, payload={'data': [{'status': 'deleted'} for _ in pubkeys]}
        )

    # pylint: disable-next=unused-argument
    def _mocked_list_pubkeys_endpoint(url, **kwargs) -> CallbackResult:
        # noqa:
        return CallbackResult(
            status=200, payload=list(_remote_signer_pubkey_privkey_mapping.keys())  # type: ignore
        )

    def _mocked_sign_endpoint(url, **kwargs) -> CallbackResult:
        public_key_to_sign_for = url.path.split('/')[-1]

        try:
            corresponding_private_key = _remote_signer_pubkey_privkey_mapping[
                public_key_to_sign_for
            ]
        except KeyError:
            return CallbackResult(status=404, body='Not Found')

        signature = bls.Sign(
            corresponding_private_key, Web3.to_bytes(hexstr=kwargs['json']['signingRoot'])
        )

        return CallbackResult(payload={'signature': f'0x{signature.hex()}'})

    with aioresponses() as m:
        # Mocked keystore import endpoint
        m.post(
            f'{remote_signer_url}/eth/v1/keystores',
            callback=_mocked_import_endpoint,
            repeat=True,
        )

        # Mocked keystore delete endpoint
        m.delete(
            f'{remote_signer_url}/eth/v1/keystores',
            callback=_mocked_delete_endpoint,
            repeat=True,
        )

        # Mocked pubkey list endpoint
        m.get(
            f'{remote_signer_url}/api/v1/eth2/publicKeys',
            callback=_mocked_list_pubkeys_endpoint,
            repeat=True,
        )

        # Mocked signing endpoint
        m.post(
            re.compile(f'^{remote_signer_url}/api/v1/eth2/sign/\\w{{98}}$'),
            callback=_mocked_sign_endpoint,
            repeat=True,
        )
        yield
