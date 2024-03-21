import random
from typing import Callable

import milagro_bls_binding as bls
import pytest
from eth_typing import BLSSignature
from eth_typing.bls import BLSPubkey
from sw_utils import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork, ProtocolConfig
from web3 import Web3

from src.config.settings import settings
from src.validators.keystores.local import LocalKeystore
from src.validators.keystores.remote import RemoteSignerKeystore
from src.validators.signing.common import get_encrypted_exit_signature_shards
from src.validators.signing.tests.oracle_functions import OracleCommittee
from src.validators.typings import ExitSignatureShards


class TestGetEncryptedExitSignatureShards:
    @staticmethod
    def check_signature_shards(
        shards: ExitSignatureShards,
        committee: OracleCommittee,
        validator_pubkey: BLSPubkey,
        validator_index: int,
        fork: ConsensusFork,
        exit_signature: BLSSignature | None = None,
    ):
        committee.verify_signature_shards(
            validator_pubkey=validator_pubkey,
            validator_index=validator_index,
            fork=fork,
            exit_signature_shards=shards,
            exit_signature=exit_signature,
        )

        # If less than exit_signature_recover_threshold signatures are used,
        # the signature should not be possible to reconstruct
        with pytest.raises(AssertionError, match='Unable to reconstruct full signature'):
            committee.exit_signature_recover_threshold -= 1
            committee.verify_signature_shards(
                validator_pubkey=validator_pubkey,
                validator_index=validator_index,
                fork=fork,
                exit_signature_shards=shards,
            )
        # Revert the change to exit_signature_recover_threshold
        committee.exit_signature_recover_threshold += 1

    @pytest.mark.usefixtures('fake_settings')
    @pytest.mark.parametrize(
        ['_mocked_oracle_committee'],
        [
            pytest.param((1, 1), id='Single oracle'),
            pytest.param((10, 5), id='10 oracles with recovery threshold of 5'),
            pytest.param((10, 10), id='10 oracles with recovery threshold of 10'),
        ],
        indirect=True,
    )
    async def test_local(
        self,
        create_validator_keypair: Callable,
        fork: ConsensusFork,
        mocked_protocol_config: ProtocolConfig,
        _mocked_oracle_committee: OracleCommittee,
    ):
        validator_privkey, validator_pubkey = create_validator_keypair()
        validator_index = 123

        keystore = LocalKeystore({validator_pubkey: validator_privkey})
        shards = await get_encrypted_exit_signature_shards(
            keystore=keystore,
            validator_index=validator_index,
            public_key=validator_pubkey,
            protocol_config=mocked_protocol_config,
            fork=fork,
        )

        self.check_signature_shards(
            shards=shards,
            committee=_mocked_oracle_committee,
            validator_pubkey=BLSPubkey(Web3.to_bytes(hexstr=validator_pubkey)),
            validator_index=validator_index,
            fork=fork,
        )

    @pytest.mark.parametrize(
        ['_mocked_oracle_committee'],
        [
            pytest.param((1, 1), id='Single oracle'),
            pytest.param((10, 5), id='10 oracles with recovery threshold of 5'),
            pytest.param((10, 10), id='10 oracles with recovery threshold of 10'),
        ],
        indirect=True,
    )
    async def test_remote_signer(
        self,
        create_validator_keypair: Callable,
        fork: ConsensusFork,
        remote_signer_url: str,
        mocked_protocol_config: ProtocolConfig,
        remote_signer_keystore: RemoteSignerKeystore,
        _mocked_oracle_committee: OracleCommittee,
    ):
        keystore = remote_signer_keystore
        validator_pubkey = keystore.public_keys[0]
        validator_index = random.randint(1, 10000)

        exit_signature = await keystore.get_exit_signature(validator_index, validator_pubkey, fork)

        shards = await get_encrypted_exit_signature_shards(
            keystore=keystore,
            validator_index=validator_index,
            public_key=validator_pubkey,
            protocol_config=mocked_protocol_config,
            fork=fork,
        )

        self.check_signature_shards(
            shards=shards,
            committee=_mocked_oracle_committee,
            validator_pubkey=BLSPubkey(Web3.to_bytes(hexstr=validator_pubkey)),
            validator_index=validator_index,
            fork=fork,
            exit_signature=exit_signature,
        )

    @pytest.mark.usefixtures('fake_settings')
    @pytest.mark.parametrize(
        ['_mocked_oracle_committee'],
        [
            pytest.param((1, 1), id='Single oracle'),
            pytest.param((10, 5), id='10 oracles with recovery threshold of 5'),
            pytest.param((10, 10), id='10 oracles with recovery threshold of 10'),
        ],
        indirect=True,
    )
    async def test_api(
        self,
        create_validator_keypair: Callable,
        fork: ConsensusFork,
        mocked_protocol_config: ProtocolConfig,
        _mocked_oracle_committee: OracleCommittee,
    ):
        """
        The case when settings.validators_registration_mode == ValidatorsRegistrationMode.API.
        Exit signature is created by third party.
        """
        validator_privkey, validator_pubkey = create_validator_keypair()
        validator_index = 123

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )
        exit_signature = bls.Sign(validator_privkey, message)

        shards = await get_encrypted_exit_signature_shards(
            keystore=None,
            validator_index=validator_index,
            public_key=validator_pubkey,
            protocol_config=mocked_protocol_config,
            fork=fork,
            exit_signature=exit_signature,
        )

        self.check_signature_shards(
            shards=shards,
            committee=_mocked_oracle_committee,
            validator_pubkey=BLSPubkey(Web3.to_bytes(hexstr=validator_pubkey)),
            validator_index=validator_index,
            fork=fork,
            exit_signature=exit_signature,
        )

    @pytest.mark.usefixtures('mocked_remote_signer')
    async def test_remote_signer_pubkey_not_present(
        self,
        create_validator_keypair: Callable,
        fork: ConsensusFork,
        mocked_protocol_config: ProtocolConfig,
        remote_signer_url: str,
        fake_settings: None,
    ):
        _, bls_pubkey = create_validator_keypair()
        validator_index = 123
        settings.remote_signer_url = remote_signer_url
        keystore = RemoteSignerKeystore([])

        with pytest.raises(RuntimeError, match='Failed to get signature'):
            _ = await get_encrypted_exit_signature_shards(
                keystore=keystore,
                validator_index=validator_index,
                public_key=bls_pubkey,
                protocol_config=mocked_protocol_config,
                fork=fork,
            )
