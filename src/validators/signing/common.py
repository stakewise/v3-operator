from typing import Sequence

import ecies
from eth_typing import BLSPubkey, BLSSignature, ChecksumAddress, HexStr
from sw_utils import ConsensusFork, ProtocolConfig, get_exit_message_signing_root
from sw_utils.signing import compute_deposit_data
from web3 import Web3

from src.common.typings import ValidatorType
from src.config.settings import settings
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.key_shares import bls_signature_and_public_key_to_shares
from src.validators.typings import ExitSignatureShards, Validator
from src.validators.utils import get_withdrawal_credentials


def encode_tx_validator_list(
    validators: Sequence[Validator], vault_address: ChecksumAddress
) -> list[bytes]:
    credentials = get_withdrawal_credentials(vault_address)
    tx_validators: list[bytes] = []
    for validator in validators:
        tx_validator = encode_tx_validator(credentials, validator)
        tx_validators.append(tx_validator)
    return tx_validators


def encode_tx_validator(withdrawal_credentials: bytes, validator: Validator) -> bytes:
    public_key = Web3.to_bytes(hexstr=validator.public_key)
    signature = Web3.to_bytes(hexstr=validator.signature)
    deposit_root = compute_deposit_data(
        public_key=public_key,
        withdrawal_credentials=withdrawal_credentials,
        amount_gwei=validator.amount,
        signature=signature,
    ).hash_tree_root
    if settings.validator_type == ValidatorType.ONE:
        return public_key + signature + deposit_root
    return public_key + signature + deposit_root + validator.amount.to_bytes(8, byteorder='big')


# pylint: disable-next=too-many-arguments
async def get_encrypted_exit_signature_shards(
    keystore: BaseKeystore | None,
    public_key: HexStr,
    validator_index: int,
    protocol_config: ProtocolConfig,
    exit_signature: BLSSignature | None = None,
    fork: ConsensusFork | None = None,
) -> ExitSignatureShards:
    """
    * generates exit signature shards,
    * generates public key shards
    * encrypts exit signature shards with oracles' public keys.
    """
    fork = fork or settings.network_config.SHAPELLA_FORK
    oracle_public_keys = [oracle.public_key for oracle in protocol_config.oracles]
    message = get_exit_message_signing_root(
        validator_index=validator_index,
        genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
        fork=fork,
    )

    if exit_signature is None:
        if keystore is None:
            raise RuntimeError('keystore or exit_signature must be set')

        exit_signature = await keystore.get_exit_signature(
            validator_index=validator_index,
            public_key=public_key,
            fork=fork,
        )
    public_key_bytes = BLSPubkey(Web3.to_bytes(hexstr=public_key))
    threshold = protocol_config.exit_signature_recover_threshold
    total = len(protocol_config.oracles)

    exit_signature_shares, public_key_shares = bls_signature_and_public_key_to_shares(
        message, exit_signature, public_key_bytes, threshold, total
    )

    encrypted_exit_signature_shards = encrypt_signatures_list(
        oracle_public_keys, exit_signature_shares
    )
    return ExitSignatureShards(
        public_keys=[Web3.to_hex(p) for p in public_key_shares],
        exit_signatures=encrypted_exit_signature_shards,
    )


def encrypt_signature(oracle_pubkey: HexStr, signature: BLSSignature) -> HexStr:
    return Web3.to_hex(ecies.encrypt(oracle_pubkey, signature))


def encrypt_signatures_list(
    oracle_pubkeys: list[HexStr], signatures: list[BLSSignature]
) -> list[HexStr]:
    res: list[HexStr] = []
    for signature, oracle_pubkey in zip(signatures, oracle_pubkeys):
        res.append(encrypt_signature(oracle_pubkey, signature))
    return res
