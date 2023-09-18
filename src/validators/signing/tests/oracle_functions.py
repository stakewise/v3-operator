import random

import ecies
import milagro_bls_binding as bls
from eth_typing.bls import BLSPubkey, BLSSignature
from sw_utils import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.config.settings import settings
from src.validators.signing.key_shares import (
    get_aggregate_key,
    reconstruct_shared_bls_signature,
)
from src.validators.typings import ExitSignatureShards


class OracleCommittee:
    def __init__(
        self,
        oracle_privkeys: list[ecies.PrivateKey],
        oracle_pubkeys: list[ecies.PublicKey],
        exit_signature_recover_threshold: int,
    ):
        self.oracle_privkeys = oracle_privkeys
        self.oracle_pubkeys = oracle_pubkeys
        self.exit_signature_recover_threshold = exit_signature_recover_threshold

    def verify_signature_shards(
        self,
        validator_pubkey: BLSPubkey,
        validator_index: int,
        fork: ConsensusFork,
        exit_signature_shards: ExitSignatureShards,
    ):
        # Decrypt the signature shards using the oracle private keys
        exit_signatures_decrypted = []
        for oracle_privkey, exit_signature_shard in zip(
            self.oracle_privkeys, exit_signature_shards.exit_signatures
        ):
            exit_signatures_decrypted.append(
                BLSSignature(
                    ecies.decrypt(oracle_privkey.secret, Web3.to_bytes(hexstr=exit_signature_shard))
                )
            )

        # Verify the pubkey shares reconstruct into the full validator pubkey
        validator_pubkey_shares = {
            idx: BLSPubkey(Web3.to_bytes(hexstr=s))
            for idx, s in enumerate(exit_signature_shards.public_keys)
        }
        aggregate_key = get_aggregate_key(validator_pubkey_shares)
        assert aggregate_key == validator_pubkey

        # Verify the signature (shards)
        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )
        for idx, (signature, validator_pubkey_share) in enumerate(
            zip(exit_signatures_decrypted, exit_signature_shards.public_keys)
        ):
            pubkey = Web3.to_bytes(hexstr=validator_pubkey_share)
            assert bls.Verify(pubkey, message, signature) is True

        # Verify the full reconstructed signature
        signatures = dict(enumerate(exit_signatures_decrypted))
        random_indexes = random.sample(sorted(signatures), k=self.exit_signature_recover_threshold)
        random_signature_subset = {k: v for k, v in signatures.items() if k in random_indexes}
        reconstructed_full_signature = reconstruct_shared_bls_signature(random_signature_subset)
        assert (
            bls.Verify(aggregate_key, message, reconstructed_full_signature) is True
        ), 'Unable to reconstruct full signature'
