import milagro_bls_binding as bls
from eth_typing import HexStr
from sw_utils.signing import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import settings
from src.validators.signing.common import encrypt_signature
from src.validators.signing.key_shares import private_key_to_private_key_shares
from src.validators.typings import BLSPrivkey, ExitSignatureShards


def get_exit_signature_shards(
    validator_index: int, private_key: BLSPrivkey, oracles: Oracles, fork: ConsensusFork
) -> ExitSignatureShards:
    """Generates exit signature shards and encrypts them with oracles' public keys."""
    message = get_exit_message_signing_root(
        validator_index=validator_index,
        genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
        fork=fork,
    )

    private_key_shares = private_key_to_private_key_shares(
        private_key=private_key,
        threshold=oracles.exit_signature_recover_threshold,
        total=len(oracles.public_keys),
    )
    exit_signature_shards: list[HexStr] = []
    for bls_priv_key, oracle_pubkey in zip(private_key_shares, oracles.public_keys):
        exit_signature_shards.append(
            encrypt_signature(oracle_pubkey, bls.Sign(bls_priv_key, message))
        )

    return ExitSignatureShards(
        public_keys=[Web3.to_hex(bls.SkToPk(priv_key)) for priv_key in private_key_shares],
        exit_signatures=exit_signature_shards,
    )
