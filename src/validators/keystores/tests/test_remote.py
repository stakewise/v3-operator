import re
from typing import Callable

import milagro_bls_binding as bls
import pytest
from aioresponses import CallbackResult, aioresponses
from eth_typing import BLSPubkey
from web3 import Web3

from src.config.networks import NETWORKS
from src.config.settings import settings
from src.validators.keystores.remote import RemoteSignerKeystore
from src.validators.utils import get_withdrawal_credentials


class TestRemoteSignerGetDepositData:
    @pytest.mark.usefixtures('fake_settings')
    async def test_get_deposit_data(
        self,
        remote_signer_keystore: RemoteSignerKeystore,
    ):
        public_key = remote_signer_keystore.public_keys[0]
        amount = 32_000_000_000

        deposit_data = await remote_signer_keystore.get_deposit_data(
            public_key=public_key, amount=amount
        )

        public_key_bytes = BLSPubkey(Web3.to_bytes(hexstr=public_key))
        signing_root = remote_signer_keystore._get_deposit_signing_root(
            public_key=public_key_bytes,
            withdrawal_credentials=get_withdrawal_credentials(),
            amount=amount,
            fork_version=NETWORKS[settings.network].GENESIS_FORK_VERSION,
        )

        assert deposit_data['pubkey'] == public_key_bytes
        assert bls.Verify(public_key_bytes, signing_root, deposit_data['signature'])

    @pytest.mark.usefixtures('fake_settings')
    async def test_get_deposit_data_wrong_signature(
        self,
        remote_signer_url: str,
        create_validator_keypair: Callable,
    ):
        _, public_key = create_validator_keypair()
        wrong_private_key, wrong_public_key = create_validator_keypair()
        # create_validator_keypair draws a random index from a fixed mnemonic
        assert wrong_public_key != public_key

        def _mocked_sign_endpoint(url, **kwargs) -> CallbackResult:
            signature = bls.Sign(
                wrong_private_key, Web3.to_bytes(hexstr=kwargs['json']['signing_root'])
            )
            return CallbackResult(payload={'signature': f'0x{signature.hex()}'})

        settings.remote_signer_url = remote_signer_url
        keystore = RemoteSignerKeystore([public_key])

        with aioresponses() as mocked_responses:
            mocked_responses.post(
                re.compile(f'^{remote_signer_url}/api/v1/eth2/sign/\\w{{98}}$'),
                callback=_mocked_sign_endpoint,
                repeat=True,
            )

            with pytest.raises(RuntimeError, match='Deposit signature verification failed'):
                await keystore.get_deposit_data(public_key=public_key, amount=32_000_000_000)
