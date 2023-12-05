from typing import Callable

import pytest
from eth_typing.bls import BLSPubkey
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import settings
from src.validators.keystores.hashi_vault import (
    HashiVaultConfiguration,
    HashiVaultKeystore,
)
from src.validators.keystores.local import LocalKeystore
from src.validators.keystores.remote import RemoteSignerKeystore
from src.validators.signing.tests.oracle_functions import OracleCommittee
from src.validators.typings import ExitSignatureShards


class TestSigning:
    @staticmethod
    def check_signature_shards(
        shards: ExitSignatureShards,
        committee: OracleCommittee,
        validator_pubkey: BLSPubkey,
        validator_index: int,
        fork: ConsensusFork,
    ):
        committee.verify_signature_shards(
            validator_pubkey=validator_pubkey,
            validator_index=validator_index,
            fork=fork,
            exit_signature_shards=shards,
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
    async def test_get_exit_signature_shards_local(
        self,
        create_validator_keypair: Callable,
        fork: ConsensusFork,
        mocked_oracles: Oracles,
        _mocked_oracle_committee: OracleCommittee,
    ):
        validator_privkey, validator_pubkey = create_validator_keypair()
        validator_index = 123

        shards = await LocalKeystore(
            {validator_pubkey: validator_privkey}
        ).get_exit_signature_shards(
            validator_index=validator_index,
            public_key=validator_pubkey,
            oracles=mocked_oracles,
            fork=fork,
        )

        TestSigning.check_signature_shards(
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
    async def test_get_exit_signature_shards_remote_signer(
        self,
        create_validator_keypair: Callable,
        fork: ConsensusFork,
        remote_signer_url: str,
        mocked_oracles: Oracles,
        remote_signer_keystore: RemoteSignerKeystore,
        _mocked_oracle_committee: OracleCommittee,
    ):
        validator_index = 123
        settings.remote_signer_url = remote_signer_url
        '''
        validator_pubkey_shares=[
                    BLSPubkey(Web3.to_bytes(hexstr=share)) for share in pubkey_shares
                ],
        '''
        for pubkey, pubkey_shares in remote_signer_keystore.pubkeys_to_shares.items():
            shards = await remote_signer_keystore.get_exit_signature_shards(
                validator_index=validator_index,
                public_key=pubkey,
                oracles=mocked_oracles,
                fork=fork,
            )

            TestSigning.check_signature_shards(
                shards=shards,
                committee=_mocked_oracle_committee,
                validator_pubkey=BLSPubkey(Web3.to_bytes(hexstr=pubkey)),
                validator_index=validator_index,
                fork=fork,
            )

    @pytest.mark.usefixtures('mocked_remote_signer')
    async def test_remote_signer_pubkey_not_present(
        self,
        create_validator_keypair: Callable,
        fork: ConsensusFork,
        mocked_oracles: Oracles,
        remote_signer_url: str,
        fake_settings: None,
    ):
        _, bls_pubkey = create_validator_keypair()
        validator_index = 123
        settings.remote_signer_url = remote_signer_url
        '''
        [BLSPubkey(Web3.to_bytes(hexstr=bls_pubkey))]
        '''
        with pytest.raises(RuntimeError, match='Failed to get signature'):
            _ = await RemoteSignerKeystore({}).get_exit_signature_shards(
                validator_index=validator_index,
                public_key=bls_pubkey,
                oracles=mocked_oracles,
                fork=fork,
            )

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_loading(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_path = 'ethereum/signing/keystores'

        config = HashiVaultConfiguration.from_settings()

        keystore = await HashiVaultKeystore._load_hashi_vault_keys(config)

        assert len(keystore) == 2

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_not_configured(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_token = None
        settings.hashi_vault_key_path = None

        with pytest.raises(RuntimeError, match='URL, token and key path must be specified'):
            await HashiVaultConfiguration.from_settings()

    @pytest.mark.usefixtures('mocked_hashi_vault')
    async def test_hashi_vault_keystores_inaccessible(
        self,
        hashi_vault_url: str,
    ):
        settings.hashi_vault_url = hashi_vault_url
        settings.hashi_vault_token = 'Secret'
        settings.hashi_vault_key_path = 'ethereum/inaccessible/keystores'

        with pytest.raises(
            RuntimeError, match='Can not retrieve validator signing keys from hashi vault'
        ):
            config = HashiVaultConfiguration.from_settings()
            await HashiVaultKeystore._load_hashi_vault_keys(config)
