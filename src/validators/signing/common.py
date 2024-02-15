import ecies
from eth_typing import BLSPubkey, BLSSignature, HexStr
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from sw_utils import get_eth1_withdrawal_credentials, get_exit_message_signing_root
from sw_utils.signing import compute_deposit_data
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import DEPOSIT_AMOUNT_GWEI, settings
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.key_shares import bls_signature_and_public_key_to_shares
from src.validators.typings import ExitSignatureShards, Validator


def encrypt_signature(oracle_pubkey: HexStr, signature: BLSSignature) -> HexStr:
    return Web3.to_hex(ecies.encrypt(oracle_pubkey, signature))


def encrypt_signatures_list(
    oracle_pubkeys: list[HexStr], signatures: list[BLSSignature]
) -> list[HexStr]:
    res: list[HexStr] = []
    for signature, oracle_pubkey in zip(signatures, oracle_pubkeys):
        res.append(encrypt_signature(oracle_pubkey, signature))
    return res


def get_validators_proof(
    tree: StandardMerkleTree,
    validators: list[Validator],
) -> tuple[list[bytes], MultiProof]:
    credentials = get_eth1_withdrawal_credentials(settings.vault)
    tx_validators: list[bytes] = []
    leaves: list[tuple[bytes, int]] = []
    for validator in validators:
        tx_validator = encode_tx_validator(credentials, validator)
        tx_validators.append(tx_validator)
        leaves.append((tx_validator, validator.deposit_data_index))

    multi_proof = tree.get_multi_proof(leaves)
    return tx_validators, multi_proof


def encode_tx_validator(withdrawal_credentials: bytes, validator: Validator) -> bytes:
    public_key = Web3.to_bytes(hexstr=validator.public_key)
    signature = Web3.to_bytes(hexstr=validator.signature)
    deposit_root = compute_deposit_data(
        public_key=public_key,
        withdrawal_credentials=withdrawal_credentials,
        amount_gwei=DEPOSIT_AMOUNT_GWEI,
        signature=signature,
    ).hash_tree_root
    return public_key + signature + deposit_root


async def get_encrypted_exit_signature_shards(
    keystore: BaseKeystore | None,
    public_key: HexStr,
    validator_index: int,
    oracles: Oracles,
    exit_signature: BLSSignature | None = None,
) -> ExitSignatureShards:
    """
    * generates exit signature shards,
    * generates public key shards
    * encrypts exit signature shards with oracles' public keys.
    """
    message = get_exit_message_signing_root(
        validator_index=validator_index,
        genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
        fork=settings.network_config.SHAPELLA_FORK,
    )

    if exit_signature is None:
        if keystore is None:
            raise RuntimeError('keystore or exit_signature must be set')

        exit_signature = await keystore.get_exit_signature(
            validator_index=validator_index,
            public_key=public_key,
        )
    public_key_bytes = BLSPubkey(Web3.to_bytes(hexstr=public_key))
    threshold = oracles.exit_signature_recover_threshold
    total = len(oracles.public_keys)

    exit_signature_shares, public_key_shares = bls_signature_and_public_key_to_shares(
        message, exit_signature, public_key_bytes, threshold, total
    )

    encrypted_exit_signature_shards = encrypt_signatures_list(
        oracles.public_keys, exit_signature_shares
    )
    return ExitSignatureShards(
        public_keys=[Web3.to_hex(p) for p in public_key_shares],
        exit_signatures=encrypted_exit_signature_shards,
    )
