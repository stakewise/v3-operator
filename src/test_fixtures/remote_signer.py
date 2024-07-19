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

    def _mocked_keymanager_import_endpoint(url, **kwargs) -> CallbackResult:
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

    def _mocked_keymanager_delete_endpoint(url, **kwargs) -> CallbackResult:
        data = kwargs['json']
        pubkeys = data['pubkeys']

        for pubkey in pubkeys:
            _remote_signer_pubkey_privkey_mapping.pop(pubkey)

        return CallbackResult(
            status=200, payload={'data': [{'status': 'deleted'} for _ in pubkeys]}
        )

    def _mocked_keymanager_list_endpoint(url, **kwargs) -> CallbackResult:
        return CallbackResult(
            status=200,
            payload={
                'data': [
                    {'validating_pubkey': pubkey}
                    for pubkey in _remote_signer_pubkey_privkey_mapping.keys()
                ]
            },
        )

    def _mocked_get_public_keys_endpoint(url, **kwargs) -> CallbackResult:
        return CallbackResult(
            status=200,
            payload=[pubkey for pubkey in _remote_signer_pubkey_privkey_mapping.keys()],
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
            corresponding_private_key, Web3.to_bytes(hexstr=kwargs['json']['signing_root'])
        )

        return CallbackResult(payload={'signature': f'0x{signature.hex()}'})

    with aioresponses() as m:
        # Mocked keymanager list keys endpoint
        m.get(
            f'{remote_signer_url}/eth/v1/keystores',
            callback=_mocked_keymanager_list_endpoint,
            repeat=True,
        )

        # Mocked keymanager get public keys endpoint
        m.get(
            f'{remote_signer_url}/api/v1/eth2/publicKeys',
            callback=_mocked_get_public_keys_endpoint,
            repeat=True,
        )

        # Mocked keymanager import keystores endpoint
        m.post(
            f'{remote_signer_url}/eth/v1/keystores',
            callback=_mocked_keymanager_import_endpoint,
            repeat=True,
        )

        # Mocked keymanager delete keys endpoint
        m.delete(
            f'{remote_signer_url}/eth/v1/keystores',
            callback=_mocked_keymanager_delete_endpoint,
            repeat=True,
        )

        # Mocked signing endpoint
        m.post(
            re.compile(f'^{remote_signer_url}/api/v1/eth2/sign/\\w{{98}}$'),
            callback=_mocked_sign_endpoint,
            repeat=True,
        )
        yield
