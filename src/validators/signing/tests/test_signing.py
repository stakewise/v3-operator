from typing import Callable

import pytest
from eth_typing.bls import BLSPubkey
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import settings
from src.validators.signing.local import get_exit_signature_shards
from src.validators.signing.remote import (
    RemoteSignerConfiguration,
    get_exit_signature_shards_remote_signer,
)
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

        shards = get_exit_signature_shards(
            validator_index=validator_index,
            private_key=validator_privkey,
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
        remote_signer_config: RemoteSignerConfiguration,
        _mocked_oracle_committee: OracleCommittee,
    ):
        validator_index = 123
        settings.remote_signer_url = remote_signer_url

        for pubkey, pubkey_shares in remote_signer_config.pubkeys_to_shares.items():
            shards = await get_exit_signature_shards_remote_signer(
                validator_index=validator_index,
                validator_pubkey_shares=[
                    BLSPubkey(Web3.to_bytes(hexstr=share)) for share in pubkey_shares
                ],
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
    ):
        _, bls_pubkey = create_validator_keypair()
        validator_index = 123
        settings.remote_signer_url = remote_signer_url

        with pytest.raises(RuntimeError, match='Failed to get signature'):
            _ = await get_exit_signature_shards_remote_signer(
                validator_index=validator_index,
                validator_pubkey_shares=[BLSPubkey(Web3.to_bytes(hexstr=bls_pubkey))],
                oracles=mocked_oracles,
                fork=fork,
            )
