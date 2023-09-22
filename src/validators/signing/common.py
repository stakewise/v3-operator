import ecies
from eth_typing import BLSSignature, HexStr
from multiproof import StandardMerkleTree
from multiproof.standard import MultiProof
from sw_utils import get_eth1_withdrawal_credentials
from sw_utils.signing import compute_deposit_data
from web3 import Web3

from src.config.settings import DEPOSIT_AMOUNT_GWEI, settings
from src.validators.typings import Validator


def encrypt_signature(oracle_pubkey: HexStr, signature: BLSSignature) -> HexStr:
    return Web3.to_hex(ecies.encrypt(oracle_pubkey, signature))


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
