from typing import Any

from eth_typing import BLSPubkey, BLSSignature
from py_ecc.bls.ciphersuites import G2ProofOfPossession
from web3 import Web3


def to_bls_pubkey(v: Any) -> BLSPubkey:
    try:
        pubkey = BLSPubkey(Web3.to_bytes(hexstr=v))
        if G2ProofOfPossession.KeyValidate(pubkey):
            return pubkey
    except Exception:  # nosec
        pass

    raise ValueError('invalid public key')


def to_bls_signature(v: Any) -> BLSSignature:
    try:
        signature = BLSSignature(Web3.to_bytes(hexstr=v))
        # pylint: disable=protected-access
        if G2ProofOfPossession._is_valid_signature(signature):
            return signature
    except Exception:  # nosec
        pass

    raise ValueError('invalid bls signature')
